// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package resources

import (
	"time"

	"github.com/golang/protobuf/ptypes"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
)

const (
	UpstreamHost = "www.envoyproxy.io"
	UpstreamPort = 80
)

func MakeCluster(clusterName string) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       ptypes.DurationProto(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		//LoadAssignment:       makeEndpoint(clusterName, UpstreamHost),
		DnsLookupFamily:  cluster.Cluster_V4_ONLY,
		EdsClusterConfig: makeEDSCluster(),
	}
}

func makeEDSCluster() *cluster.Cluster_EdsClusterConfig {
	return &cluster.Cluster_EdsClusterConfig{
		EdsConfig: makeConfigSource(),
	}
}

func MakeEndpoint(clusterName string, eps []Endpoint) *endpoint.ClusterLoadAssignment {
	var endpoints []*endpoint.LbEndpoint

	for _, e := range eps {
		endpoints = append(endpoints, &endpoint.LbEndpoint{
			HostIdentifier: &endpoint.LbEndpoint_Endpoint{
				Endpoint: &endpoint.Endpoint{
					Address: &core.Address{
						Address: &core.Address_SocketAddress{
							SocketAddress: &core.SocketAddress{
								Protocol: core.SocketAddress_TCP,
								Address:  e.UpstreamHost,
								PortSpecifier: &core.SocketAddress_PortValue{
									PortValue: e.UpstreamPort,
								},
							},
						},
					},
				},
			},
		})
	}

	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: endpoints,
		}},
	}
}

func MakeRoute(routes []Route) *route.RouteConfiguration {
	var rts []*route.Route

	for _, r := range routes {
		rts = append(rts, &route.Route{
			Name: r.Name,
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: r.Prefix,
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: r.Cluster,
					},
				},
			},
		})
	}

	return &route.RouteConfiguration{
		Name: "listener_0",
		VirtualHosts: []*route.VirtualHost{{
			Name:    "local_service",
			Domains: []string{"*"},
			Routes:  rts,
		}},
	}
}

func MakeHTTPListener(listenerName, route, address string, port uint32) *listener.Listener {
	// HTTP filter configuration
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    makeConfigSource(),
				RouteConfigName: "listener_0",
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name: wellknown.Router,
		}},
	}
	pbst, err := ptypes.MarshalAny(manager)
	if err != nil {
		panic(err)
	}

	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}
}

func MakeHTTPSListener(listenerName, address string, port uint32, snis []SNI) *listener.Listener {
	filterChains := make([]*listener.FilterChain, 0, len(snis))
	for _, sni := range snis {
		sdsTls := makeDownstreamTlsContext(sni.SecretNames)
		sdsCfg, err := ptypes.MarshalAny(sdsTls)
		if err != nil {
			panic(err)
		}

		filters := make([]*listener.Filter, 0, len(sni.Routes))
		// HTTP filter configuration
		manager := &hcm.HttpConnectionManager{
			CodecType:  hcm.HttpConnectionManager_AUTO,
			StatPrefix: "http",
			RouteSpecifier: &hcm.HttpConnectionManager_Rds{
				Rds: &hcm.Rds{
					RouteConfigName: "listener_0",
					ConfigSource:    makeConfigSource(),
				},
			},
			HttpFilters: []*hcm.HttpFilter{{
				Name: wellknown.Router,
			}},
		}
		pbst, err := ptypes.MarshalAny(manager)
		if err != nil {
			panic(err)
		}
		filters = append(filters, &listener.Filter{
			Name: wellknown.HTTPConnectionManager,
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: pbst,
			},
		})

		filterChains = append(filterChains, &listener.FilterChain{
			FilterChainMatch: makeFilterChainMatch(sni.ServerNames),
			TransportSocket: &core.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &core.TransportSocket_TypedConfig{
					TypedConfig: sdsCfg,
				},
			},
			Filters: filters,
		})
	}

	return &listener.Listener{
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  address,
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
		FilterChains: filterChains,
	}
}

func makeConfigSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "xds_cluster"},
				},
			}},
		},
	}
	return source
}

func MakeSecret(name string, key, crt []byte) *auth.Secret {
	return &auth.Secret{
		Name: name,
		Type: &auth.Secret_TlsCertificate{
			TlsCertificate: &auth.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{InlineBytes: crt},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{InlineBytes: key},
				},
			},
		},
	}
}

func makeSdsSecretConfig(secretName string) *auth.SdsSecretConfig {
	return &auth.SdsSecretConfig{
		Name: secretName,
		SdsConfig: &core.ConfigSource{
			ConfigSourceSpecifier: &core.ConfigSource_Ads{
				Ads: &core.AggregatedConfigSource{},
			},
			ResourceApiVersion: core.ApiVersion_V3,
		},
	}
}

func makeDownstreamTlsContext(secretNames []string) *auth.DownstreamTlsContext {
	sdsSecretConfigs := make([]*auth.SdsSecretConfig, 0, len(secretNames))
	for _, secretName := range secretNames {
		sdsSecretConfigs = append(sdsSecretConfigs, makeSdsSecretConfig(secretName))
	}
	return &auth.DownstreamTlsContext{
		CommonTlsContext: &auth.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: sdsSecretConfigs,
		},
	}
}

func makeFilterChainMatch(serverNames []string) *listener.FilterChainMatch {
	return &listener.FilterChainMatch{
		ServerNames: serverNames,
	}
}

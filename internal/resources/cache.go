//   Copyright Steve Sloka 2021
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

type Listener struct {
	Name       string
	Address    string
	Port       uint32
	RouteNames []string
}

type Route struct {
	Name    string
	Prefix  string
	Cluster string
}

type Cluster struct {
	Name      string
	Endpoints []Endpoint
}

type Endpoint struct {
	UpstreamHost string
	UpstreamPort uint32
}

type TLSListener struct {
	Name    string
	Address string
	Port    uint32
	SNIs    []SNI
}

type SNI struct {
	SecretNames []string
	ServerNames []string
	Routes      []Route
}

type Secret struct {
	Name             string
	PrivateKey       []byte
	CertificateChain []byte
}

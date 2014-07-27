package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"runtime"
	"encoding/json"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	runtime.GOMAXPROCS(runtime.NumCPU())
	rand.Seed(time.Now().UnixNano())
	if t, ok := http.DefaultClient.Transport.(*http.Transport); ok {
		t.MaxIdleConnsPerHost = 4
	}
}

const (
	Timeout = time.Second * 5
)

type ProxyBackend struct {
	Addr string
	Type string
}

type TConf struct {
	Proxies   []string `json:"proxies"`
	BlackList []string   `json:"blacks"`

	blacklist []*regexp.Regexp
	proxies   []ProxyBackend
}

func splitHostAndPort(host string) (string, uint16) {
	if idx := strings.Index(host, ":"); idx < 0 {
		return host, 80
	} else {
		port, _ := strconv.Atoi(host[idx + 1:])
		return host[:idx], uint16(port)
	}
}

func (s *ProxyBackend) Dial(d time.Duration, r string) (con net.Conn, err error) {
	if oconn, err := net.DialTimeout("tcp", s.Addr, d); err == nil {
		// socks5: http://www.ietf.org/rfc/rfc1928.txt
		oconn.Write([]byte{ // VERSION_AUTH
		5, // PROTO_VER5
		1, //
		0, // NO_AUTH
	})
		buffer := [64]byte{}
		oconn.Read(buffer[:])

		buffer[0] = 5 // VER  5
		buffer[1] = 1 // CMD connect
		buffer[2] = 0 // RSV
		buffer[3] = 3 // DOMAINNAME: X'03'

		host, port := splitHostAndPort(r)
		hostBytes := []byte(host)
		buffer[4] = byte(len(hostBytes))
		copy(buffer[5:], hostBytes)
		binary.BigEndian.PutUint16(buffer[5+len(hostBytes):], uint16(port))
		oconn.Write(buffer[:5 + len(hostBytes) + 2])

		if n, err := oconn.Read(buffer[:]); n > 1 && err == nil && buffer[1] == 0 {
			return oconn, nil
		} else {
			return nil, fmt.Errorf("connet to socks server %s error: %v", s.Addr, err)
		}
	} else {
		return nil, err
	}
}

type Server struct {
	cfg *TConf
}

func (s *Server) isBlocked(host string) bool {
	host, _ = splitHostAndPort(host)
	bytes := []byte(host)

	for _, r := range s.cfg.blacklist {
		if r.Find(bytes) != nil {
			return true
		}
	}
	return false
}

func (s *Server) getProxy() ProxyBackend {
	return s.cfg.proxies[rand.Intn(len(s.cfg.proxies))]
}

func NewProxyServer(conf string) (*Server, error) {
	if data, err := ioutil.ReadFile(conf); err == nil {
		cfg := &TConf{}
		if err := json.Unmarshal(data, cfg); err == nil {
			for _, b := range cfg.BlackList {
				if r, err := regexp.Compile(b); err == nil {
					cfg.blacklist = append(cfg.blacklist, r)
				} else {
					log.Printf("WARN, compile regex %v, got err: %v", r, err)
				}
			}
			for _, p := range cfg.Proxies {
				cfg.proxies = append(cfg.proxies, ProxyBackend{Addr:p})
			}
			log.Printf("load %v proxies, with %v rules from %v",
				len(cfg.proxies), len(cfg.blacklist), conf)
			return &Server {
				cfg: cfg,
			}, nil
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

func (s *Server) fetchDirectly(w http.ResponseWriter, ireq *http.Request) {
	if req, err := http.NewRequest(ireq.Method, ireq.URL.String(), ireq.Body); err == nil {
		for k, values := range ireq.Header {
			for _, v := range values {
				req.Header.Add(k, v)
			}
		}
		req.ContentLength = ireq.ContentLength
		// do not follow any redirect， browser will do that
		if resp, err := http.DefaultTransport.RoundTrip(req); err == nil {
			for k, values := range resp.Header {
				for _, v := range values {
					w.Header().Add(k, v)
				}
			}
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}
	}
}

func copyConn(iconn net.Conn, oconn net.Conn) {
	buffer := [4096]byte{}
	defer iconn.Close()
	defer oconn.Close()
	for {
		if n, err := iconn.Read(buffer[:]); err == nil {
			oconn.Write(buffer[:n])
		} else {
			return
		}
	}
}

func (s *Server) tunnelTraffic(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)

	if iconn, _, err := w.(http.Hijacker).Hijack(); err == nil {
		if s.isBlocked(r.URL.Host) {
			proxy := s.getProxy()
			log.Printf("socks tunnel by %v: %v", proxy.Addr, r.URL.Host)

			if oconn, err := proxy.Dial(Timeout, r.URL.Host); err == nil {
				go copyConn(iconn, oconn)
				go copyConn(oconn, iconn)
			} else {
				log.Println("dial socks server %v, error: %v", proxy.Addr, err)
				iconn.Close()
			}

		} else {
			log.Printf("direct tunnel %v", r.URL.Host)
			// connect directly
			if oconn, err := net.DialTimeout("tcp", r.URL.Host, Timeout); err == nil {
				go copyConn(iconn, oconn)
				go copyConn(oconn, iconn)
			} else {
				log.Printf("direct dial %v, error: %v", r.URL.Host, err)
				iconn.Close()
			}
		}
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		s.tunnelTraffic(w, r)
	} else if !s.isBlocked(r.URL.Host) {
		log.Println("directly:", r.URL)
		s.fetchDirectly(w, r)
	} else {
		if iconn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			proxy := s.getProxy()
			log.Printf("proxy by %v: %v", proxy.Addr, r.URL.Host)

			if oconn, err := proxy.Dial(Timeout, r.URL.Host); err == nil {
				r.Write(oconn)
				go copyConn(iconn, oconn)
				go copyConn(oconn, iconn)
			} else {
				log.Println("open proxy failed", proxy.Addr, err)
				iconn.Close()
			}
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func main() {
	var addr, config string
	flag.StringVar(&addr, "addr", "0.0.0.0:6666", "Which Addr the proxy listens")
	flag.StringVar(&config, "config", "config.json", "Config json path")
	flag.Parse()

	if server, err := NewProxyServer(config); err == nil {
		log.Println("Proxy multiplexer listens on", addr)
		log.Fatal(http.ListenAndServe(addr, server))
	} else {
		log.Fatal(err)
	}
}

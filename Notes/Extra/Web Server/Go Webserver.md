Certainly! I can help you create a Go webserver with all the features you've requested. This is a complex task that involves several components, so I'll create a comprehensive Go script that meets your requirements.



```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	port    = flag.Int("port", 8080, "Port to listen on")
	useTLS  = flag.Bool("tls", false, "Use HTTPS")
	logFile = flag.String("log", "server.log", "Path to log file")
)

func main() {
	flag.Parse()

	// Set up logging
	f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Set up file server with directory listing
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", logRequest(http.StripPrefix("/", fs)))

	// Set up POST handler
	http.HandleFunc("/upload", logRequest(handleUpload))

	addr := fmt.Sprintf(":%d", *port)
	var listenAndServe func() error

	if *useTLS {
		cert, key := generateSelfSignedCert()
		listenAndServe = func() error {
			return http.ListenAndServeTLS(addr, cert, key, nil)
		}
		log.Printf("Starting HTTPS server on https://localhost%s", addr)
	} else {
		listenAndServe = func() error {
			return http.ListenAndServe(addr, nil)
		}
		log.Printf("Starting HTTP server on http://localhost%s", addr)
	}

	log.Fatal(listenAndServe())
}

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		log.Printf("User-Agent: %s", r.UserAgent())

		if r.Method == "POST" {
			body, _ := ioutil.ReadAll(r.Body)
			r.Body.Close()
			r.Body = ioutil.NopCloser(strings.NewReader(string(body)))

			if len(body) <= 4096 {
				decodedBody, err := base64.StdEncoding.DecodeString(string(body))
				if err == nil {
					log.Printf("Decoded body: %s", string(decodedBody))
				} else {
					log.Printf("Body: %s", string(body))
				}
			} else {
				log.Printf("Body: [%d bytes]", len(body))
			}
		}

		next.ServeHTTP(w, r)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "uploaded_file"
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	err = ioutil.WriteFile(filename, body, 0644)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File %s uploaded successfully", filename)
}

func generateSelfSignedCert() (string, string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certFile, _ := ioutil.TempFile("", "cert*.pem")
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyFile, _ := ioutil.TempFile("", "key*.pem")
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyFile.Close()

	return certFile.Name(), keyFile.Name()
}

```

This Go script creates a webserver with the following features:

1. Customizable port: Use the `-port` flag to specify the port (default is 8080).
2. HTTP/HTTPS support: Use the `-tls` flag to enable HTTPS with a self-signed certificate.
3. Logging: All incoming requests are logged to a file specified by the `-log` flag (default is "server.log").
4. Directory listing: Enabled by default for the current directory.
5. POST request handling: 
   - Decodes base64-encoded bodies that are 4KB or smaller in the log.
   - Allows specifying a filename through a query parameter.
6. User-Agent logging: Logs the User-Agent string for all requests.

To use this server:

1. Save the script to a file, e.g., `advanced_server.go`
2. Run it with Go: `go run advanced_server.go`

You can use flags to customize the behavior:

- `go run advanced_server.go -port 9000` to run on port 9000
- `go run advanced_server.go -tls` to use HTTPS
- `go run advanced_server.go -log custom.log` to use a custom log file

To make a POST request with a specified filename:

```
curl -X POST -d "base64encodeddata" "http://localhost:8080/upload?filename=myfile.txt"
```

This server provides a good foundation for your requirements. However, please note:

1. The self-signed certificate is generated on the fly and will cause warnings in browsers.
2. There's no authentication or authorization, so be cautious about where you deploy this.
3. Large file uploads might consume a lot of memory as the entire body is read into memory.



```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	port    = flag.Int("port", 8080, "Port to listen on")
	useTLS  = flag.Bool("tls", false, "Use HTTPS")
	logFile = flag.String("log", "server.log", "Path to log file")
)

func main() {
	flag.Parse()

	// Set up logging
	f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Set up file server with directory listing
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", logRequest(http.StripPrefix("/", fs)))

	// Set up POST handler
	http.HandleFunc("/upload", logRequest(handleUpload))

	addr := fmt.Sprintf(":%d", *port)
	var listenAndServe func() error

	if *useTLS {
		cert, key := generateSelfSignedCert()
		listenAndServe = func() error {
			return http.ListenAndServeTLS(addr, cert, key, nil)
		}
		log.Printf("Starting HTTPS server on https://localhost%s", addr)
	} else {
		listenAndServe = func() error {
			return http.ListenAndServe(addr, nil)
		}
		log.Printf("Starting HTTP server on http://localhost%s", addr)
	}

	log.Fatal(listenAndServe())
}

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		log.Printf("User-Agent: %s", r.UserAgent())

		if r.Method == "POST" {
			body, _ := ioutil.ReadAll(r.Body)
			r.Body.Close()
			r.Body = ioutil.NopCloser(strings.NewReader(string(body)))

			if len(body) <= 4096 {
				decodedBody, err := base64.StdEncoding.DecodeString(string(body))
				if err == nil {
					log.Printf("Decoded body: %s", string(decodedBody))
				} else {
					log.Printf("Body: %s", string(body))
				}
			} else {
				log.Printf("Body: [%d bytes]", len(body))
			}
		}

		next.ServeHTTP(w, r)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "uploaded_file"
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	err = ioutil.WriteFile(filename, body, 0644)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File %s uploaded successfully", filename)
}

func generateSelfSignedCert() (string, string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certFile, _ := ioutil.TempFile("", "cert*.pem")
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyFile, _ := ioutil.TempFile("", "key*.pem")
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyFile.Close()

	return certFile.Name(), keyFile.Name()
}
```


## Advanced Version

Certainly! I'll modify the script to address your requests: making it multithreaded, reducing memory consumption, saving POST requests to files in a Downloads directory, and creating the Downloads directory if it doesn't exist. Here's an updated version of the script:



```go
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	port         = flag.Int("port", 8080, "Port to listen on")
	useTLS       = flag.Bool("tls", false, "Use HTTPS")
	logFile      = flag.String("log", "server.log", "Path to log file")
	downloadDir  = flag.String("downloads", "Downloads", "Directory to save uploaded files")
	maxBodySize  = int64(10 * 1024 * 1024) // 10MB max body size
)

func main() {
	flag.Parse()

	// Set up logging
	f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Create Downloads directory if it doesn't exist
	if err := os.MkdirAll(*downloadDir, 0755); err != nil {
		log.Fatalf("error creating downloads directory: %v", err)
	}

	// Set up file server with directory listing
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", logRequest(http.StripPrefix("/", fs)))

	// Set up POST handler
	http.HandleFunc("/upload", logRequest(handleUpload))

	addr := fmt.Sprintf(":%d", *port)
	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if *useTLS {
		cert, key := generateSelfSignedCert()
		log.Printf("Starting HTTPS server on https://localhost%s", addr)
		log.Fatal(server.ListenAndServeTLS(cert, key))
	} else {
		log.Printf("Starting HTTP server on http://localhost%s", addr)
		log.Fatal(server.ListenAndServe())
	}
}

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		log.Printf("User-Agent: %s", r.UserAgent())

		if r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			body = body[:n]

			if n <= 4096 {
				decodedBody, err := base64.StdEncoding.DecodeString(string(body))
				if err == nil {
					log.Printf("Decoded body: %s", string(decodedBody))
				} else {
					log.Printf("Body: %s", string(body))
				}
			} else {
				log.Printf("Body: [first 4KB of %d bytes]", r.ContentLength)
			}
		}

		next.ServeHTTP(w, r)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "uploaded_file"
	}

	// Sanitize filename
	filename = filepath.Base(filepath.Clean(filename))
	filepath := filepath.Join(*downloadDir, filename)

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	// Limit the size of the incoming request body
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	// Create a buffered reader
	reader := bufio.NewReader(r.Body)

	// Copy from the request body to the file using a buffer
	buf := make([]byte, 32*1024) // 32KB buffer
	_, err = io.CopyBuffer(out, reader, buf)
	if err != nil && err != io.EOF {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File %s uploaded successfully", filename)
}

func generateSelfSignedCert() (string, string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certFile, _ := ioutil.TempFile("", "cert*.pem")
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyFile, _ := ioutil.TempFile("", "key*.pem")
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyFile.Close()

	return certFile.Name(), keyFile.Name()
}

```

Here are the key changes and improvements:

1. Multithreading: The `http.Server` in Go is already multithreaded by default. Each incoming request is handled in its own goroutine, allowing for concurrent processing of requests.

2. Reduced memory consumption:
   - We now use `http.MaxBytesReader` to limit the size of incoming request bodies.
   - In the `logRequest` function, we only read the first 4KB of the body for logging purposes.
   - In `handleUpload`, we use `io.CopyBuffer` with a fixed-size buffer to stream the file to disk instead of loading it entirely into memory.

3. Saving POST requests to files:
   - POST requests to `/upload` are now saved to the specified Downloads directory.
   - The filename can be specified using the `filename` query parameter.
   - If no filename is provided, it defaults to "uploaded_file".

4. Creating the Downloads directory:
   - The script now creates the Downloads directory (specified by the `-downloads` flag) if it doesn't exist.

5. Additional improvements:
   - Added timeouts to the server for better resource management.
   - Implemented basic filename sanitization to prevent directory traversal attacks.
   - Set a maximum body size (10MB by default) to prevent resource exhaustion attacks.

To use this updated server:

1. Save the script to a file, e.g., `advanced_server.go`
2. Run it with Go: `go run advanced_server.go`

You can use flags to customize the behavior:

- `go run advanced_server.go -port 9000` to run on port 9000
- `go run advanced_server.go -tls` to use HTTPS
- `go run advanced_server.go -log custom.log` to use a custom log file
- `go run advanced_server.go -downloads /path/to/downloads` to specify a custom download directory

To make a POST request with a specified filename:

```
curl -X POST -d "your_data_here" "http://localhost:8080/upload?filename=myfile.txt"
```

This updated server addresses your requests for multithreading, reduced memory consumption, and saving POST requests to files in a Downloads directory. It also includes some additional security measures.

```go
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	port         = flag.Int("port", 8080, "Port to listen on")
	useTLS       = flag.Bool("tls", false, "Use HTTPS")
	logFile      = flag.String("log", "server.log", "Path to log file")
	downloadDir  = flag.String("downloads", "Downloads", "Directory to save uploaded files")
	maxBodySize  = int64(10 * 1024 * 1024) // 10MB max body size
)

func main() {
	flag.Parse()

	// Set up logging
	f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	// Create Downloads directory if it doesn't exist
	if err := os.MkdirAll(*downloadDir, 0755); err != nil {
		log.Fatalf("error creating downloads directory: %v", err)
	}

	// Set up file server with directory listing
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", logRequest(http.StripPrefix("/", fs)))

	// Set up POST handler
	http.HandleFunc("/upload", logRequest(handleUpload))

	addr := fmt.Sprintf(":%d", *port)
	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if *useTLS {
		cert, key := generateSelfSignedCert()
		log.Printf("Starting HTTPS server on https://localhost%s", addr)
		log.Fatal(server.ListenAndServeTLS(cert, key))
	} else {
		log.Printf("Starting HTTP server on http://localhost%s", addr)
		log.Fatal(server.ListenAndServe())
	}
}

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		log.Printf("User-Agent: %s", r.UserAgent())

		if r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
			body := make([]byte, 4096)
			n, _ := r.Body.Read(body)
			body = body[:n]

			if n <= 4096 {
				decodedBody, err := base64.StdEncoding.DecodeString(string(body))
				if err == nil {
					log.Printf("Decoded body: %s", string(decodedBody))
				} else {
					log.Printf("Body: %s", string(body))
				}
			} else {
				log.Printf("Body: [first 4KB of %d bytes]", r.ContentLength)
			}
		}

		next.ServeHTTP(w, r)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "uploaded_file"
	}

	// Sanitize filename
	filename = filepath.Base(filepath.Clean(filename))
	filepath := filepath.Join(*downloadDir, filename)

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	// Limit the size of the incoming request body
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	// Create a buffered reader
	reader := bufio.NewReader(r.Body)

	// Copy from the request body to the file using a buffer
	buf := make([]byte, 32*1024) // 32KB buffer
	_, err = io.CopyBuffer(out, reader, buf)
	if err != nil && err != io.EOF {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File %s uploaded successfully", filename)
}

func generateSelfSignedCert() (string, string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	certFile, _ := ioutil.TempFile("", "cert*.pem")
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certFile.Close()

	keyFile, _ := ioutil.TempFile("", "key*.pem")
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyFile.Close()

	return certFile.Name(), keyFile.Name()
}
```

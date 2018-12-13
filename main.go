package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/SermoDigital/jose/jws"
	"github.com/urfave/cli"
)

type JWKeys struct {
	Keys []JWKey `json:"keys"`
}

type JWKey struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`

	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"`
}

type JWTHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

var (
	appName, appVer string
)

func main() {
	app := cli.NewApp()
	app.Name = appName
	app.HelpName = appName
	app.Usage = "Used for quick retrieval of public key from JWK"
	app.Version = appVer
	app.Copyright = ""
	app.Authors = []cli.Author{
		{
			Name: "Rafpe ( https://rafpe.ninja )",
		},
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "out",
			Value: "RSA",
			Usage: "Output type ( RSA | PUBLIC )",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "from-server",
			Usage: "Get public key from JWKs",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url",
					Usage: "URL from which details should be retrived",
				},
				cli.StringFlag{
					Name:  "kid",
					Value: "*",
					Usage: "Select specific kid - otherwise query all",
				},
				cli.BoolFlag{
					Name:  "show-kid",
					Usage: "When more keys exists shows kid for every key",
				},
			},
			Action: cmdRetrievePublicKey,
		},
		{
			Name:  "from-token",
			Usage: "Get public key from JWKs extracted from JWT",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "token",
					Usage: "Token to be parsed",
				},
			},
			Action: cmdRetrievePublicKeyFromToken,
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Action = func(c *cli.Context) error {

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}

}

func cmdRetrievePublicKeyFromToken(c *cli.Context) error {
	verifyArgumentByName(c, "token")
	token := c.String("token")

	// Parse token to get issuer information
	parsedJWT, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return err
	}

	// Customize URL to match Okta
	issuer, _ := parsedJWT.Claims().Issuer()
	url := issuer + "/v1/keys"

	// Get kid from our JWT
	decoded, _ := base64.StdEncoding.DecodeString(strings.Split(token, ".")[0])
	jwtHeader := JWTHeader{}
	json.Unmarshal([]byte(string(decoded)+"}"), &jwtHeader)

	// retrrieve JWKs from the server
	byteArr, err := getJWK(url)
	jwsKeys := JWKeys{}
	if err = json.Unmarshal([]byte(byteArr), &jwsKeys); err != nil {
		fmt.Println(err)
	}

	// Extract public key
	extractPublicKeyFromJWK(jwsKeys, c.GlobalString("out"), jwtHeader.Kid, c.Bool("show-kid"))

	return nil
}

func cmdRetrievePublicKey(c *cli.Context) error {
	verifyArgumentByName(c, "url")
	url := c.String("url")

	// Call to retrieve JWKs - this assumes full URL has been given
	// to path where JWKs are to be retrieved from
	byteArr, err := getJWK(url)

	// retrrieve JWKs from the server
	jwsKeys := JWKeys{}
	if err = json.Unmarshal([]byte(byteArr), &jwsKeys); err != nil {
		fmt.Println(err)
	}

	// Extract public key
	extractPublicKeyFromJWK(jwsKeys, c.GlobalString("out"), c.String("kid"), c.Bool("show-kid"))

	return nil
}

// getJWK  retrieves JWKs from the provided URL
func getJWK(url string) ([]byte, error) {

	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	byt, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return byt, nil

}

func extractPublicKeyFromJWK(jwks JWKeys, outType, kid string, showKid bool) {
	for _, singleJWK := range jwks.Keys {
		if kid != "*" && kid != singleJWK.Kid {
			continue
		}

		//  c.Bool("show-kid")
		if showKid {
			fmt.Println(fmt.Sprintf("KID: %s", singleJWK.Kid))
		}

		if singleJWK.Kty != "RSA" {
			log.Fatal("invalid key type:", singleJWK.Kty)
		}

		// decode the base64 bytes for n
		nb, err := base64.RawURLEncoding.DecodeString(singleJWK.N)
		if err != nil {
			log.Fatal(err)
		}

		e := 0
		// The default exponent is usually 65537, so just compare the
		// base64 for [1,0,1] or [0,1,0,1]
		if singleJWK.E == "AQAB" || singleJWK.E == "AAEAAQ" {
			e = 65537
		} else {
			// need to decode "e" as a big-endian int
			log.Fatal("need to deocde e:", singleJWK.E)
		}

		pk := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: e,
		}

		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			log.Fatal(err)
		}

		// Define the output type of our key
		outputType := ""
		switch outType {
		case "RSA":
			outputType = "RSA PUBLIC KEY"
		case "PUBLIC":
			outputType = "PUBLIC KEY"
		}

		block := &pem.Block{
			Type:  outputType,
			Bytes: der,
		}

		var out bytes.Buffer
		pem.Encode(&out, block)
		fmt.Println(out.String())

	}
}

// verifyArgumentByName helper function to display information about
//						missing arguments
func verifyArgumentByName(c *cli.Context, argName string) {
	if c.String(argName) == "" {
		log.Fatal(fmt.Sprintf("Please provide required argument(s)! [ %s ]", argName))
	}
}

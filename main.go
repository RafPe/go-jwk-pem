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

	app.Commands = []cli.Command{
		{
			Name:  "pubkey",
			Usage: "Get public key from JWKs",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url",
					Usage: "URL from which details should be retrived",
				},
				cli.StringFlag{
					Name:  "out",
					Value: "RSA",
					Usage: "Output type ( RSA | PUBLIC )",
				},
				cli.StringFlag{
					Name:  "kid",
					Value: "*",
					Usage: "Select specific kid",
				},
				cli.BoolFlag{
					Name:  "show-kid",
					Usage: "Show kid",
				},
			},
			Action: cmdRetrievePublicKey,
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

func cmdRetrievePublicKey(c *cli.Context) error {
	VerifyArgumentByName(c, "url")
	url := c.String("url")

	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Println(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	byt, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	/*
		Print out body
	*/
	//fmt.Println(string(byt))

	jwsKeys := JWKeys{}
	if err = json.Unmarshal([]byte(byt), &jwsKeys); err != nil {
		fmt.Println(err)
	}

	for _, singleJWK := range jwsKeys.Keys {
		if c.String("kid") != "*" && c.String("kid") != singleJWK.Kid {
			continue
		}

		if c.Bool("show-kid") {
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
		switch c.String("out") {
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

	return nil
}

func VerifyArgumentByName(c *cli.Context, argName string) {
	if c.String(argName) == "" {
		log.Fatal(fmt.Sprintf("Please provide required argument(s)! [ %s ]", argName))
	}
}

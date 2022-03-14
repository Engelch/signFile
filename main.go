//go:generate swagger generate spec

// TODO: currently no support for piped mode.

package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	ce "github.com/engelch/go_libs/v2"
	cli "github.com/urfave/cli/v2"
)

const appVersion = "1.1.0"
const appName = "signfile"

// These CLI options are used more than once below. So let's use constants that we do not get
// misbehaviour by typoos.
const _debug = "debug" // long (normal) name of CLI option
const _v2 = "v2"       // long (normal) name of CLI option
const _raw = "raw"     // long (normal) name of CLI option for mode, write signature not base64 encoded

var privateKeyFile string // file containing private key
var pubKeyFile string     // file containing public key

// =======================================================================================

// PRE: data-file existing and not a directory
func verifySignature(c *cli.Context, filename string, basename string) error {
	var sigFile string
	if c.Bool(_v2) {
		sigFile = basename + ".sig2"
	} else {
		sigFile = basename + ".sig"
	}
	info, err := os.Stat(sigFile)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":stat:file " + sigFile + ":" + err.Error())
	}
	if info.IsDir() {
		return errors.New(ce.CurrentFunctionName() + ":isDir:file " + sigFile)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":readfile:file " + filename + ":" + err.Error())
	}
	signature, err := os.ReadFile(sigFile)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":readfile:file " + sigFile + ":" + err.Error())
	}
	signaturePlain, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		signaturePlain = signature
	}
	publicKey, err := ce.LoadPublicKey(pubKeyFile)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":readfile:file " + pubKeyFile + ":" + err.Error())
	}
	if c.Bool(_v2) {
		err = ce.VerifyPSSByteArray(publicKey, signaturePlain, string(data))
	} else {
		err = ce.Verify115ByteArray(publicKey, signaturePlain, string(data))
	}
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":verification:" + err.Error() + ":" + err.Error())
	}
	return nil
}

// PRE: data-file existing and not a directory
func createSignature(c *cli.Context, filename string, basename string) error {
	var sigFile string
	if c.Bool(_v2) {
		sigFile = basename + ".sig2"
	} else {
		sigFile = basename + ".sig"
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":readfile:file " + filename + ":" + err.Error())
	}
	privateKey, err := ce.LoadPrivateKey(privateKeyFile)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":readfile:file " + privateKeyFile + ":" + err.Error())
	}
	digest := ce.Sha256bytes2bytes(data)
	var signature []byte
	if c.Bool(_v2) {
		signature, err = ce.SignPSSByteArray(privateKey, digest)
	} else {
		signature, err = ce.Sign115ByteArray(privateKey, digest)
	}
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":signing:" + err.Error())
	}
	fd, err := os.Create(sigFile) // overwrite file if existing.
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":create:file " + sigFile + ":" + err.Error())
	}
	defer fd.Close()
	var n int
	var length int
	if c.Bool(_raw) {
		length = len(signature)
		n, err = fd.Write(signature)
	} else {
		b64signature := []byte(base64.StdEncoding.EncodeToString(signature))
		length = len(b64signature)
		n, err = fd.Write(b64signature)
	}
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":write, err:file " + sigFile + ":" + err.Error())
	}
	if n != length {
		return errors.New(ce.CurrentFunctionName() + ":write, number of bytes:file " + sigFile + ":len signature, written" + fmt.Sprintf("%d, %d", len(signature), n))
	}
	return nil
}

// PRE: either pubKeyFile or privateKeyFile is != ""
func signOrVerify(c *cli.Context, filename string) error {
	info, err := os.Stat(filename)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":stat:file " + filename + ":" + err.Error())
	}
	if info.IsDir() {
		return errors.New(ce.CurrentFunctionName() + ":isDir:file " + filename)
	}
	extension := filepath.Ext(filename)
	basename := filename[0 : len(filename)-len(extension)]
	ce.CondDebugln(ce.CurrentFunctionName() + ":basename is " + basename)
	if pubKeyFile != "" {
		return verifySignature(c, filename, basename)
	}
	return createSignature(c, filename, basename)
}

// =======================================================================================

// checkOptions checks the command line options if properly set or in range.
// POST: exactly one keyfile is not mt.
func checkOptions(c *cli.Context, privateKeyFile, pubKeyFile string) error {
	if c.Bool(_debug) {
		ce.CondDebugSet(true)
	}
	ce.CondDebugln("Debug is enabled.")
	if pubKeyFile == "" && privateKeyFile == "" {
		return errors.New("Public and prviate key file are not set. Mode of operation unclear.")
	}
	if pubKeyFile != "" && privateKeyFile != "" {
		return errors.New("Public and prviate key file are set. Mode of operation unclear.")
	}
	return nil
}

// commandLineOptions just separates the definition of command line options ==> creating a shorter main
func commandLineOptions(privateKeyFile *string, pubKeyFile *string) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    _debug,
			Aliases: []string{"d"},
			Value:   false,
			Usage:   "OPTIONAL: enable debug",
		},
		&cli.BoolFlag{
			Name:    _v2,
			Aliases: []string{"2"},
			Value:   false,
			Usage:   "use version 2, usually called by just OAEP and PSS instead of PKCS#1.\n The signature will have a suffix .sig2, else .sig",
		},
		&cli.BoolFlag{
			Name:    _raw,
			Aliases: []string{"r"},
			Value:   false,
			Usage:   "Write signature in pure form, not base64-encoded which is the default",
		},
		&cli.StringFlag{
			Name:        "privateKeyFile",
			Aliases:     []string{"i"},
			Usage:       "Optional: specify the file with the private key for signing",
			Destination: privateKeyFile,
		},
		&cli.StringFlag{
			Name:        "publicKeyFile",
			Aliases:     []string{"u"},
			Usage:       "Optional: specify the file with the public key for verification",
			Destination: pubKeyFile,
		},
	}
}

func warnUser(file string, errmsg string) {
	fmt.Printf("%-30s FAILED! %s\n", file, errmsg)
}

func informUser(c *cli.Context, file string) {
	if pubKeyFile != "" {
		fmt.Printf("%-30s verification OK.\n", file)
		return
	}
	var rawOption = ""
	if c.Bool(_raw) {
		rawOption = "raw "
	}
	fmt.Printf("%-30s %ssignature created.\n", file, rawOption)
}

// main start routine
func main() {
	app := cli.NewApp() // global var, see discussion above
	app.Flags = commandLineOptions(&privateKeyFile, &pubKeyFile)
	app.Name = appName
	app.Version = appVersion
	app.Usage = "\n      signFile [-d] [-r] [-2] -i <<publicKeyFile>> <<file>>... # for signing" +
		"\n      signFile [-d]      [-2] -u <<publicKeyFile>> <<file>>... # for verification"

	app.Action = func(c *cli.Context) error {
		err := checkOptions(c, privateKeyFile, pubKeyFile)
		ce.ExitIfError(err, 9, "checkOptions")
		var res uint
		if c.NArg() > 0 {
			for i := 0; i < c.NArg(); i += 1 {
				err = signOrVerify(c, c.Args().Get(i))
				if err != nil {
					warnUser(c.Args().Get(i), err.Error())
					res += 1
				} else {
					informUser(c, c.Args().Get(i))
				}
			}
		}
		if res == 0 {
			return nil
		}
		fmt.Print("Number of errors occurred: " + fmt.Sprintf("%d\n", res))
		os.Exit(1)
		return nil // never reached
	}
	_ = app.Run(os.Args)
}

// eof

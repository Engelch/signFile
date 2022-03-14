//go:generate swagger generate spec

// TODO: -q/-s for quiet mode
// TODO: base64 default
// TODO: currently no support for piped mode.
// TODO: error without stack trace like message

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	ce "github.com/engelch/go_libs/v2"
	cli "github.com/urfave/cli/v2"
)

const appVersion = "0.2.1"
const appName = "signfile"

// These CLI options are used more than once below. So let's use constants that we do not get
// misbehaviour by typoos.
const _debug = "debug"     // long (normal) name of CLI option
const _logging = "logging" // long (normal) name of CLI option
const _v2 = "v2"           // long (normal) name of CLI option

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
	publicKey, err := ce.LoadPublicKey(pubKeyFile)
	if err != nil {
		return errors.New(ce.CurrentFunctionName() + ":readfile:file " + pubKeyFile + ":" + err.Error())
	}
	if c.Bool(_v2) {
		err = ce.VerifyPSSByteArray(publicKey, signature, string(data))
	} else {
		err = ce.Verify115ByteArray(publicKey, signature, string(data))
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
	n, err := fd.Write(signature)
	if n != len(signature) {
		return errors.New(ce.CurrentFunctionName() + ":write:file " + sigFile + ":len signature, written" + fmt.Sprintf("%d, %d", len(signature), n))
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
			Name:    _logging,
			Aliases: []string{"l"},
			Value:   false,
			Usage:   "OPTIONAL: log to syslog (default: stderr)",
		},
		&cli.BoolFlag{
			Name:    _v2,
			Aliases: []string{"2"},
			Value:   false,
			Usage:   "use version 2, usually called by just OAEP and PSS instead of PKCS#1.\n The signature will have a suffix .sig2, else .sig",
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

// main start routine
func main() {
	app := cli.NewApp() // global var, see discussion above
	app.Flags = commandLineOptions(&privateKeyFile, &pubKeyFile)
	app.Name = appName
	app.Version = appVersion
	app.Usage = "signFile [-d] [-l] [-2] -i <<publicKeyFile>> <<file>>... # for signing"
	app.Usage = "signFile [-d] [-l] [-2] -u <<publicKeyFile>> <<file>>... # for verification"

	app.Action = func(c *cli.Context) error {
		if c.Bool(_logging) {
			ce.LogInit(app.Name)
		} else {
			ce.LogStringInit(app.Name)
		}
		// ce.LogInfo(app.Name + ":version " + appVersion + ":start") // this is no service
		err := checkOptions(c, privateKeyFile, pubKeyFile)
		ce.ExitIfError(err, 9, "checkOptions")
		var res uint
		if c.NArg() > 0 {
			for i := 0; i < c.NArg(); i += 1 {
				err = signOrVerify(c, c.Args().Get(i))
				if err != nil {
					ce.LogErr(err.Error())
					res += 1
				}
			}
		}
		if res == 0 {
			return nil
		}
		return errors.New("Number of errors occurred: " + fmt.Sprintf("%d\n", res))
	}
	err := app.Run(os.Args)
	if err != nil {
		panic(err.Error())
	}
}

// eof

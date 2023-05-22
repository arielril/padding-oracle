package main

import (
	"encoding/hex"

	"github.com/arielril/padding-oracle/internal/oracle"
	"github.com/arielril/padding-oracle/pkg/types"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var options = &types.Options{}

func init() {
	set := goflags.NewFlagSet()
	set.SetDescription("Padding oracle")

	set.StringVarP(&options.HexCipherMessage, "message", "msg", "", "cipher message to attack")
	set.IntVar(&options.BlockSize, "block-size", 16, "block size (8, 16, 32)")

	set.BoolVarP(&options.Verbose, "verbose", "v", false, "verbose output")
	set.BoolVarP(&options.Silent, "silent", "s", false, "silent output")

	if err := set.Parse(); err != nil {
		gologger.Fatal().Msgf("could not parse flags: %s\n", err)
	}
}

func main() {
	err := validateOptions(options)
	if err != nil {
		gologger.Fatal().Msgf("could not run padding oracle: %s\n", err)
	}

	configureOutput(options)

	gologger.Info().Msg("padding oracle :P")

	o := oracle.New("http://crypto-class.appspot.com/po?er=", options.BlockSize)
	o.Exploit(options)

}

func validateOptions(opts *types.Options) error {
	if opts.HexCipherMessage == "" {
		return errors.New("empty cipher message input")
	}

	a, err := hex.DecodeString(opts.HexCipherMessage)
	if err != nil {
		return errors.Wrap(err, "could not decode cipher message")
	}
	opts.CipherMessage = a

	if opts.BlockSize == 0 || opts.BlockSize%8 != 0 {
		return errors.New("block size is not 8, 16 or 32")
	}

	return nil
}

func configureOutput(opts *types.Options) {
	if opts.Verbose && opts.Silent {
		gologger.Fatal().Msg("silent and verbose output can not be set at the same time")
	}

	if opts.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	if opts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

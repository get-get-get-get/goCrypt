package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/get-get-get-get/goCrypt/pkg/encrypt"
	"github.com/get-get-get-get/goCrypt/pkg/keys"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file using RSA private key",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("decrypt called")

		// Path to file to be encrypted
		file, err := filepath.Abs(args[0])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Encrypting file:", file)

		// Output path
		o, err := cmd.Flags().GetString("output")
		if err != nil {
			log.Fatal(err)
		}
		// If no output given, encrypt the file in place
		if o == "" {
			o = file
		}
		out, err := filepath.Abs(o)
		if err != nil {
			log.Fatal(err)
		}

		// Key
		k, err := cmd.Flags().GetString("key")
		if err != nil {
			log.Fatal(err)
		}
		key := keys.PrivateKeyFromFile(k)
		fmt.Println("Read private key! Validity", key.Validate())

		// Encrypt data
		dec, err := encrypt.RSADecryptFile(file, key)
		if err != nil {
			log.Fatal(err)
		}
		// Save decrypted data
		if err := ioutil.WriteFile(out, dec, 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("File decrypted!")
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringP("key", "k", "", "Path to private key")
	decryptCmd.Flags().StringP("output", "o", "", "Output decrypted content as")
}

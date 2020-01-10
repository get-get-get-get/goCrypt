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

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "A brief description of your command",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("encrypt called")

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

		// Public key
		p, err := cmd.Flags().GetString("pubkey")
		if err != nil {
			log.Fatal(err)
		}
		pub := keys.PublicKeyFromFile(p)
		fmt.Println("Read public key! Size: ", pub.Size())

		// Encrypt data
		enc, err := encrypt.RSAEncryptFile(file, pub)
		if err != nil {
			log.Fatal(err)
		}
		// Save encrypted data
		if err := ioutil.WriteFile(out, enc, 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("File Encrypted!")

	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().StringP("pubkey", "p", "", "Path to public key")
	encryptCmd.Flags().StringP("output", "o", "", "Output encrypted content as")
}

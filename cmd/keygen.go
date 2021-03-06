package cmd

import (
	"fmt"
	"log"

	"github.com/get-get-get-get/goCrypt/pkg/keys"
	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Create an RSA keypair",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keygen called")

		// Keysize should be some power of two >= 1024
		keysize, err := cmd.Flags().GetInt("size")
		if err != nil {
			log.Fatal(err)
		}

		// Output is private key output file. Public key appends ".pub"
		output, err := cmd.Flags().GetString("output")
		if err != nil {
			log.Fatal(err)
		}

		// Create and save keys
		kg := keys.NewKeyGenerator(output, keysize)
		kg.Save()
		fmt.Println("RSA keypair created!")
		fmt.Println("Private key:", kg.KeyFile)
		fmt.Println("Public key:", kg.PublicKeyFile)

	},
}

func init() {
	rootCmd.AddCommand(keygenCmd)

	keygenCmd.Flags().StringP("output", "o", "rsa", "Output to file")
	keygenCmd.Flags().IntP("size", "s", 2048, "Key size")
}

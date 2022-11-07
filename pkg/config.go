package tinkaeadcli

// KeyTemplate defines the template for tink.
type KeyTemplate string

// Config defines necessary fields to initial an EncrypterDecrypter.
type Config struct {
	// Key template for aead or streaming_aead
	Template KeyTemplate
	// KeyURI can only be started with gcp-kms://
	// If KeyFile not presented, use envelope encryption, otherwise use remote KEK to decrypt local KeyFile.
	KeyURI string
	// Credentials file for accessing kms
	Credentials string
	// KeyFile for local DEK encryption, optional.
	KeyFile string
}

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testdata

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
)

var PEMBytes map[string][]byte

func init() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	config := api.DefaultConfig()
	if vaultAddr != "" {
		config.Address = vaultAddr
	}

	client, err := api.NewClient(config)
	if err != nil {
		log.Fatalf("failed to create Vault client: %v", err)
	}

	if vaultToken != "" {
		client.SetToken(vaultToken)
	}

	secret, err := client.Logical().Read("secret/data/pr0thi-mongo-ssh-testdata-keys-256cb2e9")
	if err != nil {
		log.Fatalf("failed to read secret from Vault: %v", err)
	}
	if secret == nil || secret.Data == nil || secret.Data["data"] == nil {
		log.Fatalf("secret not found or empty at 'secret/data/pr0thi-mongo-ssh-testdata-keys-256cb2e9'")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		log.Fatalf("invalid secret data format")
	}

	rsaKey, ok := data["secret"].(string)
	if !ok {
		log.Fatalf("secret key 'secret' not found or not a string in Vault")
	}

	PEMBytes = map[string][]byte{
		"dsa": []byte(`-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQD6PDSEyXiI9jfNs97WuM46MSDCYlOqWw80ajN16AohtBncs1YB
lHk//dQOvCYOsYaE+gNix2jtoRjwXhDsc25/IqQbU1ahb7mB8/rsaILRGIbA5WH3
EgFtJmXFovDz3if6F6TzvhFpHgJRmLYVR8cqsezL3hEZOvvs2iH7MorkxwIVAJHD
nD82+lxh2fb4PMsIiaXudAsBAoGAQRf7Q/iaPRn43ZquUhd6WwvirqUj+tkIu6eV
2nZWYmXLlqFQKEy4Tejl7Wkyzr2OSYvbXLzo7TNxLKoWor6ips0phYPPMyXld14r
juhT24CrhOzuLMhDduMDi032wDIZG4Y+K7ElU8Oufn8Sj5Wge8r6ANmmVgmFfynr
FhdYCngCgYEA3ucGJ93/Mx4q4eKRDxcWD3QzWyqpbRVRRV1Vmih9Ha/qC994nJFz
DQIdjxDIT2Rk2AGzMqFEB68Zc3O+Wcsmz5eWWzEwFxaTwOGWTyDqsDRLm3fD+QYj
nOwuxb0Kce+gWI8voWcqC9cyRm09jGzu2Ab3Bhtpg8JJ8L7gS3MRZK4CFEx4UAfY
Fmsr0W6fHB9nhS4/UXM8
-----END DSA PRIVATE KEY-----
`),
		"ecdsa": []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINGWx0zo6fhJ/0EAfrPzVFyFC9s18lBt3cRoEDhS3ARooAoGCCqGSM49
AwEHoUQDQgAEi9Hdw6KvZcWxfg2IDhA7UkpDtzzt6ZqJXSsFdLd+Kx4S3Sx4cVO+
6/ZOXRnPmNAlLUqjShUsUBBngG0u2fqEqA==
-----END EC PRIVATE KEY-----
`),
		"rsa": []byte(rsaKey),
		"user": []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILYCAeq8f7V4vSSypRw7pxy8yz3V5W4qg8kSC3zJhqpQoAoGCCqGSM49
AwEHoUQDQgAEYcO2xNKiRUYOLEHM7VYAp57HNyKbOdYtHD83Z4hzNPVC4tM5mdGD
PLL8IEwvYu2wq+lpXfGQnNMbzYf9gspG0w==
-----END EC PRIVATE KEY-----
`),
	}
}
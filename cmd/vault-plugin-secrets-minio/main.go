package main

import (
    "os"

    minio "github.com/jayxiong1/vault-plugin-secrets-minio/plugin"
    hclog "github.com/hashicorp/go-hclog"
    "github.com/hashicorp/vault/api"
    "github.com/hashicorp/vault/sdk/plugin"
)

func main() {
    apiClientMeta := &api.PluginAPIClientMeta{}
    flags := apiClientMeta.FlagSet()
    flags.Parse(os.Args[1:])

    tlsConfig := apiClientMeta.GetTLSConfig()
    tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

    err := plugin.ServeMultiplex(&plugin.ServeOpts{
        BackendFactoryFunc: minio.Factory,
        TLSProviderFunc:    tlsProviderFunc,
    })
    if err != nil {
        logger := hclog.New(&hclog.LoggerOptions{})

        logger.Error("plugin shutting down", "error", err)
        os.Exit(1)
    }
}

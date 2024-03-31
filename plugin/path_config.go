package minio

import (
    "context"

    "github.com/hashicorp/errwrap"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

const (
    configStoragePath = "config"
)

// Define the CRU functions for the config path
func (b *minioBackend) pathConfigCRUD() *framework.Path {
    return &framework.Path{
    Pattern: "config",
    HelpSynopsis: "Configure the Minio connection.",
    HelpDescription: "Use this endpoint to set the Minio endpoint, accessKeyId, secretAccessKey and SSL settings.",

    Fields: map[string]*framework.FieldSchema{
        "endpoint": &framework.FieldSchema{
        Type: framework.TypeString,
        Description: "The Minio server endpoint.",
        },
        "accessKeyId": &framework.FieldSchema{
        Type: framework.TypeString,
        Description: "The Minio administrative key ID.",
        },
        "secretAccessKey": &framework.FieldSchema{
        Type: framework.TypeString,
        Description: "The Minio administrative secret access key.",
        },
        "useSSL": &framework.FieldSchema{
        Type: framework.TypeBool,
        Description: "(Optional, default `false`) Use SSL to connect to the Minio server.",
        },
    },

    Operations: map[logical.Operation]framework.OperationHandler{
        logical.ReadOperation: &framework.PathOperation{
            Callback: b.pathConfigRead,
        },
        logical.UpdateOperation: &framework.PathOperation{
            Callback: b.pathConfigUpdate,
        },
        logical.DeleteOperation: &framework.PathOperation{
            Callback: b.pathConfigDelete,
        },
    },
    }
}

// Read the current configuration
func (b *minioBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
    c, err := b.GetConfig(ctx, req.Storage);
    if err != nil {
        return nil, err
    }

    return &logical.Response{
    Data: map[string]interface{}{
        "endpoint": c.Endpoint,
        "accessKeyId": c.AccessKeyId,
        "secretAccessKey": c.SecretAccessKey,
        "useSSL": c.UseSSL,
    },
    }, nil
}

// Update the configuration
func (b *minioBackend) pathConfigUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    c, err := b.GetConfig(ctx, req.Storage);
    if err != nil {
        return nil, err
    }

    // Update the internal configuration
    changed, err := c.Update(d)
    if err != nil {
        return nil, err
    }

    // If we changed the configuration, store it
    if changed {
        // Make a new storage entry
        entry, err := logical.StorageEntryJSON(configStoragePath, c)
        if err != nil {
            return nil, errwrap.Wrapf("failed to generate JSON configuration: {{err}}", err)
        }

        // And store it
        if err := req.Storage.Put(ctx, entry); err != nil {
            return nil, errwrap.Wrapf("Failed to persist configuration: {{err}}", err)
        }

    }

    // Destroy any old client which may exist so we get a new one
    // with the next request
    b.invalidateMadminClient()

    return nil, nil
}

func (b *minioBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    err := req.Storage.Delete(ctx, configStoragePath)

    if err == nil {
        b.invalidateMadminClient()
        return nil, nil
    }

    return nil, errwrap.Wrapf("failed to delete configuration: {{err}}", err)
}
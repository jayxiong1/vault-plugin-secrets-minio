package minio

import (
    "context"
    "fmt"
    "time"

    "github.com/hashicorp/errwrap"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func (b *minioBackend) pathKeysRead() *framework.Path {
    return &framework.Path{
        Pattern:      fmt.Sprintf("creds/" + framework.GenericNameRegex("role")),
        HelpSynopsis: "Provision a key for this role.",

        Fields: map[string]*framework.FieldSchema{
            "role": &framework.FieldSchema{
                Type:        framework.TypeString,
                Description: "Name of role.",
            },
            "policy": &framework.FieldSchema{
                Type:        framework.TypeString,
                Description: "Policy in JSON format",
            },
            "sts_ttl": &framework.FieldSchema{
                Type:        framework.TypeDurationSecond,
                Description: "Lifetime of accessKey in seconds.",
            },
            "sts": &framework.FieldSchema{
                Type: framework.TypeBool,
                Default: false,
                Description: "Flag to verify if the application needs sts or user static credentials.",
            },
        },

        Operations: map[logical.Operation]framework.OperationHandler{
            logical.UpdateOperation: &framework.PathOperation{
                Callback: b.pathKeysCreate,
            },
            logical.DeleteOperation: &framework.PathOperation{
                Callback: b.pathKeysRevoke,
            },
        },
    }
}

func (b *minioBackend) pathKeysCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    var resp map[string]interface{}
    roleName := d.Get("role").(string)
    sts := d.Get("sts").(bool)

    role, err := b.GetRole(ctx, req.Storage, roleName)
    if err != nil {
        return nil, errwrap.Wrapf("error fetching role: {{err}}", err)
    }

    userCreds, err := b.getUserCredential(ctx, req, roleName, role)
    if err != nil {
        return nil, err
    }

    if sts {
        var sts_ttl time.Duration
        ttl := time.Duration(d.Get("sts_ttl").(int)) * time.Second

        if ttl == 0 {
            sts_ttl = role.StsMaxTTL
        } else {
            sts_ttl = ttl
        }

        policy := d.Get("policy").(string)

        newKey, err := b.getSTS(ctx, req, userCreds, policy, sts_ttl)
        if err != nil {
            return nil, err
        }

        // Gin up response
        resp = map[string]interface{}{
            "accessKeyId":     newKey.AccessKeyID,
            "secretAccessKey": newKey.SecretAccessKey,
            "ttl":             sts_ttl.Seconds(),
        }
    } else {
        // Gin up response
        resp = map[string]interface{}{
            "accessKeyId":     userCreds.AccessKeyID,
            "secretAccessKey": userCreds.SecretAccessKey,
            "policy_name":     role.PolicyName,
            "ttl":             0,
            "userAccountStatus": userCreds.Status,
        }
    }

    return &logical.Response{
        Data: resp,
    }, nil
}

func (b *minioBackend) pathKeysRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
    role := d.Get("role").(string)
    err := b.removeUser(ctx, req, role)

    if err != nil {
        return nil, err
    }

    return nil, nil
}

func (b *minioBackend) getUserCredential(ctx context.Context, req *logical.Request, roleName string, role *Role) (*UserInfo, error) {
    // Getting user details from vault
    userInfo, err := b.getUserInfo(ctx, req.Storage, roleName)
    if err != nil {
        return nil, err
    }

    if userInfo == nil {
        var newKeyName string
        if role.UserNamePrefix == "" {
            newKeyName = fmt.Sprintf("%s", req.ID)
        } else {
            newKeyName = fmt.Sprintf("%s-%s", role.UserNamePrefix, req.ID)
        }

        // if user is not present in vault create new and add user to vault
        userInfo, err = b.addUser(ctx, req, newKeyName, role.PolicyName, roleName)
        if err != nil {
            return nil, err
        }
    }
    return userInfo, nil
}
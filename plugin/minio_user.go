package minio

import (
    "context"
    "time"

    "encoding/base64"

    "github.com/hashicorp/errwrap"
    uuid "github.com/hashicorp/go-uuid"
    "github.com/hashicorp/vault/sdk/logical"
    "github.com/minio/madmin-go/v3"
    cr "github.com/minio/minio-go/v7/pkg/credentials"
)

const (
    userStoragePath = "users"
    minioSecretKeyLength = 32
    scheme = "https"
)
// UserInfo carries information about long term users.
type UserInfo struct {
    AccessKeyID     string                `json:"accessKeyId,omitempty"`
    SecretAccessKey string                `json:"secretAccessKey,omitempty"`
    PolicyName      string                `json:"policyName,omitempty"`
    Status          madmin.AccountStatus  `json:"status"`
}

func (b *minioBackend) getUserInfo(ctx context.Context, s logical.Storage, roleName string) (*UserInfo, error) {	
    userMap, err := b.getUserMapFromStorage(ctx, s)
    if err != nil {
        return nil, err
    }

    userInfo, ok := userMap[roleName]
    if ok {
        return &userInfo, nil
    }

    b.Logger().Info("This roleName", roleName, "is not found in userMap from persistent storage!")
    return nil, nil
}

func (b *minioBackend) addUser(ctx context.Context, req *logical.Request, userAccesskey string,
    policy string, roleName string) (*UserInfo, error) {
    b.Logger().Info("Adding user by madmin client and persisting it inside local storage")

    client, err := b.getMadminClient(ctx, req.Storage)
    if err != nil {
        return nil, err
    }

    secretAccessKey, err := b.generateSecretAccessKey()
    if err != nil {
        return nil, err
    }

    err = client.AddUser(ctx, userAccesskey, secretAccessKey)
    if err != nil {
        b.Logger().Error("Adding minio user failed", "userAccesskey", userAccesskey,"error", err)
        return nil, err
    }

    // Setting policy to minio user.
    err = client.SetPolicy(ctx,  policy, userAccesskey, false)
    if err != nil {
        b.Logger().Error("Setting minio user policy failed", "minoUserAccesskey", userAccesskey, 
        "policy", policy, "error", err)
        return nil, err
    }

     // Gin up the madmin.UserInfo struct
    userInfo := UserInfo{
        AccessKeyID: userAccesskey,
        SecretAccessKey: secretAccessKey,
        PolicyName: policy,
        Status: madmin.AccountEnabled,
    }
    //Update map with userInfo
    userMap, err := b.getUserMapFromStorage(ctx, req.Storage)
    if err != nil {
        return nil, err
    }

    userMap[roleName] = userInfo

    entry, err := logical.StorageEntryJSON(userStoragePath, userMap)
    if err != nil {
        return nil, errwrap.Wrapf("failed to generate JSON configuration when adding user details: {{err}}", err)
    }

    if err := req.Storage.Put(ctx, entry); err != nil {
        return nil, errwrap.Wrapf("Failed to persist user in storage: {{err}}", err)
    }

    // Destroy any old client which may exist so we get a new one
    // with the next request
    b.invalidateMadminClient()

    return &userInfo, nil 
}

func (b *minioBackend) getSTS(ctx context.Context, req *logical.Request, userInfo *UserInfo,
    policy string, ttl time.Duration)  (cr.Value, error) {

    b.Logger().Info("Getting STS credentials")
    var stsEndpoint string

    config, err := b.GetConfig(ctx, req.Storage)
    if err != nil {
        return cr.Value{}, err
    }
    stsEndpoint = scheme + "://" + config.Endpoint
    var stsOpts cr.STSAssumeRoleOptions
    stsOpts.AccessKey = userInfo.AccessKeyID
    stsOpts.SecretKey = userInfo.SecretAccessKey
    stsOpts.Policy = string(policy)
    stsOpts.DurationSeconds = int(ttl.Seconds())

    credsObject, err := cr.NewSTSAssumeRole(stsEndpoint, stsOpts)
    if err != nil {
        return cr.Value{}, err
    }

    v, err := credsObject.Get()
    if err != nil {
        return cr.Value{}, err
    }

    return v, nil
}

func (b *minioBackend) removeUser(ctx context.Context, req *logical.Request, roleName string) (error) {
    userInfo, err := b.getUserInfo(ctx, req.Storage, roleName)
    if err != nil {
        return errwrap.Wrapf("failed to receive user info from local storage: {{err}}", err)
    }

    if userInfo != nil {
        b.Logger().Info("Removing user by madmin client")
        client, err := b.getMadminClient(ctx, req.Storage)
        if err != nil {
            return errwrap.Wrapf("failed to receive madmin client: {{err}}", err)
        }
        if err = client.RemoveUser(ctx, userInfo.AccessKeyID); err != nil {
            return errwrap.Wrapf("failed to delete user access by madmin: {{err}}", err)
        }
    
        b.Logger().Info("Removing roleName", roleName, " and user details from user map, updating userMap in the persistent storage")
        userMap, err := b.getUserMapFromStorage(ctx, req.Storage)
        if err != nil {
            return err
        }
        delete(userMap, roleName)
    
        entry, err := logical.StorageEntryJSON(userStoragePath, userMap)
        if err != nil {
            return errwrap.Wrapf("failed to generate JSON configuration when adding user details: {{err}}", err)
        }
    
        if err := req.Storage.Put(ctx, entry); err != nil {
            return errwrap.Wrapf("Failed to persist user in persistent storage: {{err}}", err)
        }
    } else {
        b.Logger().Info("This roleName", roleName, " and user info may already be deleted or not present in local storage")
    }
    
    b.invalidateMadminClient()
    return nil
}

func (b *minioBackend) generateSecretAccessKey() (string, error) {
    b.Logger().Info("Generating secrect access key for user")
    randBytes, err := uuid.GenerateRandomBytes(minioSecretKeyLength)

    if err != nil {
        return "", errwrap.Wrapf("Error generating random bytes: {{err}}", err)
    }

    return base64.StdEncoding.EncodeToString(randBytes), nil
}

func (b *minioBackend) getUserMapFromStorage(ctx context.Context, s logical.Storage) (map[string]UserInfo, error) {
    b.Logger().Info("Retrieving user info stored in persistent storage")

    entry, err := s.Get(ctx, userStoragePath);
    if err != nil {
        return  nil, errwrap.Wrapf("Failed to get user entry map from persistent storage: {{err}}", err)
    }

    var userMap = make(map[string]UserInfo)

    //if there is no userInfo present in local storage return empty map
    if entry == nil {
        return userMap, nil
    }
    
    if err := entry.DecodeJSON(&userMap); err != nil {
        return nil, errwrap.Wrapf("failed to decode user entry map: {{err}}", err)
    }

    return userMap, nil
}
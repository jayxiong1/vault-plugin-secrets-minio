package minio_test

import (
    "context"
    "testing"

    "github.com/hashicorp/vault/sdk/logical"
    "github.com/minio/madmin-go/v3"
    "github.com/stretchr/testify/require"
    minio "github.com/kula/vault-plugin-secrets-minio/plugin"
)

const (
    TEST_STS_TTL = 50
    TEST_POLICY  = "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n   {\n    \"Effect\": \"Allow\",\n    \"Action\": [\n     \"s3:GetBucketLocation\",\n     \"s3:GetObject\"\n    ],\n    \"Resource\": [\n     \"arn:aws:s3:::*\"\n    ]\n   }\n  ]\n }"
    TEST_STS     = false
)

func TestPluginPathKeysCreateError(t *testing.T) {
    reqStorage := new(logical.InmemStorage)

    t.Run("Test Path Keys Api Generate STS Error When Role Not Found", func(t *testing.T) {
        resp, err := testPathKeysCreate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "sts_ttl": TEST_STS_TTL,
            "policy":  TEST_POLICY,
            "sts":     TEST_STS,
        })
        require.Error(t, err)
        require.Nil(t, resp)
    })

    t.Run("Test Path Keys Api Generate STS Error When Getting Minio Admin Client Returns Error", func(t *testing.T) {
        _, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":      TEST_STS_MAX_TTL,
        })
        require.NoError(t, err)

        resp, err := testPathKeysCreate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "sts_ttl": TEST_STS_TTL,
            "policy":  TEST_POLICY,
            "sts":     TEST_STS,
        })
        require.Error(t, err)
        require.Nil(t, resp)
    })

    t.Run("Test Path Keys Api Retrive User Static Credential Returns Error", func(t *testing.T) {
        _, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":      TEST_STS_MAX_TTL,
        })
        require.NoError(t, err)
        resp, err := testPathKeysCreate(t, reqStorage, TEST_ROLE_NAME, nil)
        require.Error(t, err)
        require.Nil(t, resp)
    })
}

func TestPluginPathKeysRevokeError(t *testing.T) {

    t.Run("Test Path Keys Api Revoke Error When Retrieving Role Details", func(t *testing.T) {
        reqStorage := new(logical.InmemStorage)
        reqStorage.Underlying().FailGet(true)
        resp, err := testPathKeysRevoke(t, reqStorage, TEST_ROLE_NAME)
        require.Error(t, err)
        require.Nil(t, resp)
    })

    t.Run("Test Path Keys Api Revoke Error When Updating UserInfoMap", func(t *testing.T) {
        reqStorage := new(logical.InmemStorage)
        testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":      TEST_STS_MAX_TTL,
        })

        userInfo := minio.UserInfo{
            AccessKeyID:     "userAccesskey",
            SecretAccessKey: "secretAccessKey",
            PolicyName:      "policy",
            Status:          madmin.AccountEnabled,
        }

        var userMap = make(map[string]minio.UserInfo)
        userMap[TEST_ROLE_NAME] = userInfo
        entry, _ := logical.StorageEntryJSON("users", userMap)
        reqStorage.Put(context.Background(), entry)

        reqStorage.Underlying().FailPut(true)
        resp, err := testPathKeysRevoke(t, reqStorage, TEST_ROLE_NAME)
        require.Error(t, err)
        require.Nil(t, resp)
    })
}

func testPathKeysCreate(t *testing.T, s logical.Storage, roleName string, d map[string]interface{}) (*logical.Response, error) {
    t.Helper()
    b, _ := getMinioBackend(t)
    return b.HandleRequest(context.Background(), &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "creds/" + roleName,
        Data:      d,
        Storage:   s,
    })
}

func testPathKeysRevoke(t *testing.T, s logical.Storage, roleName string) (*logical.Response, error) {
    t.Helper()
    return minio.Backend().HandleRequest(context.Background(), &logical.Request{
        Operation: logical.DeleteOperation,
        Path:      "creds/" + roleName,
        Storage:   s,
    })
}

func getMinioBackend(_ testing.TB) (logical.Backend, error) {
    config := logical.TestBackendConfig()
    config.System = logical.TestSystemView()
    return minio.Factory(context.Background(), config)
}
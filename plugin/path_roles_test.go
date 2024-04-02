package minio_test

import (
    "context"
    "strconv"
    "testing"

    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/require"
    "github.com/minio/madmin-go/v3"
    minio "github.com/kula/vault-plugin-secrets-minio/plugin"
)

const (
    TEST_ROLE_NAME       = "test"
    TEST_USERNAME_PREFIX = "test_prefix"
    TEST_POLICY_NAME     = "readonly"
    TEST_STS_MAX_TTL     = 100
)

func TestPluginRoleSuccess(t *testing.T) {
    reqStorage := new(logical.InmemStorage)

    t.Run("Test Role Apis With No Error", func(t *testing.T) {
        _, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })
        require.NoError(t, err)

        resp, _ := testRoleRead(t, reqStorage, TEST_ROLE_NAME)
        if resp == nil {
            t.Fatalf("Error: received nil response")
        }
        require.Equal(t, TEST_USERNAME_PREFIX, resp.Data["user_name_prefix"])
        require.Equal(t, TEST_POLICY_NAME, resp.Data["policy_name"])
        require.Equal(t, float64(TEST_STS_MAX_TTL), resp.Data["sts_max_ttl"])

        // Updating Role details
        testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": "new_prefix",
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })

        resp, _ = testRoleRead(t, reqStorage, TEST_ROLE_NAME)
        if resp == nil {
            t.Fatalf("Error: received nil response")
        }
        require.Equal(t, "new_prefix", resp.Data["user_name_prefix"])
        require.Equal(t, TEST_POLICY_NAME, resp.Data["policy_name"])
        require.Equal(t, float64(TEST_STS_MAX_TTL), resp.Data["sts_max_ttl"])

        _, err = testRoleDelete(t, reqStorage, TEST_ROLE_NAME)
        require.NoError(t, err)

        // Reading a deleted role
        _, err = testRoleRead(t, reqStorage, TEST_ROLE_NAME)
        require.Error(t, err)

    })

    t.Run("Test Role Existance Check Success", func(t *testing.T) {
        _, err := testRoleCreateOrUpdate(t, reqStorage, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })
        require.NoError(t, err)

        checkFound, exists, err := testRoleExistanceCheck(t, reqStorage, map[string]interface{}{
            "role": TEST_ROLE_NAME})
        require.True(t, checkFound)
        require.True(t, exists)
        require.Nil(t, err)
    })
}

func TestPluginRoleList(t *testing.T) {
    reqStorage := new(logical.InmemStorage)
    t.Run("Test List All Roles Api Success", func(t *testing.T) {
        for i := 1; i <= 3; i++ {
            resp, err := testRoleCreateOrUpdate(t, reqStorage,
                TEST_ROLE_NAME+strconv.Itoa(i),
                map[string]interface{}{
                    "role":             TEST_ROLE_NAME,
                    "user_name_prefix": TEST_USERNAME_PREFIX,
                    "policy_name":      TEST_POLICY_NAME,
                    "sts_max_ttl":		TEST_STS_MAX_TTL,
                },
            )
            if resp.IsError() {
                t.Fatalf("Error: received error response: %v", resp.Error().Error())
            }
            require.NoError(t, err)
        }

        resp, err := testRoleList(t, reqStorage)
        require.NoError(t, err)
        require.Len(t, resp.Data["keys"].([]string), 3)
    })

    t.Run("Test List All Roles Api Failure", func(t *testing.T) {
        reqStorage.Underlying().FailList(true)
        resp, err := testRoleList(t, reqStorage)
        require.Error(t, err)
        require.Nil(t, resp)
    })
}

func TestPluginRoleWriteError(t *testing.T) {
    reqStorage := new(logical.InmemStorage)

    t.Run("Test Role Write Error With No Role", func(t *testing.T) {
        resp, err := testRoleCreateOrUpdate(t, reqStorage, "", map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })

        require.Nil(t, resp.Error())
        require.Error(t, err)
    })

    t.Run("Test Role Write Error When Put Api Returns Error", func(t *testing.T) {
        s := &logical.InmemStorage{}
        s.Underlying().FailPut(true)

        resp, err := testRoleCreateOrUpdate(t, s, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })
        require.Nil(t, resp)
        require.Error(t, err)
    })
}

func TestPluginRoleDelete(t *testing.T) {
    s := &logical.InmemStorage{}
    t.Run("Test Role Error When Delete Api Returns Error", func(t *testing.T) {
        s.Underlying().FailDelete(true)
        resp, _ := testRoleCreateOrUpdate(t, s, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })
        require.NoError(t, resp.Error())

        _, err := testRoleDelete(t, s, TEST_ROLE_NAME)
        require.Error(t, err)
    })

    t.Run("Test Role Delete That Does Not Exist", func(t *testing.T) {
        s.Underlying().FailGet(true)

        _, err := testRoleDelete(t, s, TEST_ROLE_NAME)
        require.Error(t, err)
    })

    t.Run("Test Role Delete Remove Static User Credential When STS is False", func(t *testing.T) {
        s := &logical.InmemStorage{}
        _, err := testRoleCreateOrUpdate(t, s, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })
        require.NoError(t, err)

        _, err = testRoleDelete(t, s, TEST_ROLE_NAME)
        require.NoError(t, err)
    })

    t.Run("Test Role Delete Remove Static User Credential Error When STS is False", func(t *testing.T) {
        s := &logical.InmemStorage{}
        _, err := testRoleCreateOrUpdate(t, s, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })
        require.NoError(t, err)

        userInfo := minio.UserInfo{
            AccessKeyID: "userAccesskey",
            SecretAccessKey: "secretAccessKey",
            PolicyName: "policy",
            Status: madmin.AccountEnabled,
        }

        var userMap = make(map[string]minio.UserInfo)
        userMap[TEST_ROLE_NAME] = userInfo
        entry, _ := logical.StorageEntryJSON("users", userMap)
        s.Put(context.Background(), entry)

        s.Underlying().FailPut(true)

        _, err = testRoleDelete(t, s, TEST_ROLE_NAME)
        require.Error(t, err)
    })
}

func TestPluginReadError(t *testing.T) {
    reqStorage := new(logical.InmemStorage)
    t.Run("Test Role Read Role Not Found", func(t *testing.T) {
        resp, err := testRoleRead(t, reqStorage, TEST_ROLE_NAME)

        require.Error(t, resp.Error())
        require.Error(t, err)
    })

    t.Run("Test Role List Role Not Found", func(t *testing.T) {
        resp, err := testRoleList(t, reqStorage)

        require.Nil(t, resp.Error())
        require.Nil(t, err)
    })
    t.Run("Test Role Read Error When Get Api Returns Error", func(t *testing.T) {
        s := &logical.InmemStorage{}
        s.Underlying().FailGet(true)
        
        _, err := testRoleCreateOrUpdate(t, s, TEST_ROLE_NAME, map[string]interface{}{
            "role":             TEST_ROLE_NAME,
            "user_name_prefix": TEST_USERNAME_PREFIX,
            "policy_name":      TEST_POLICY_NAME,
            "sts_max_ttl":		TEST_STS_MAX_TTL,
        })
        require.NoError(t, err)

        resp, err := testRoleRead(t, s, TEST_ROLE_NAME)

        require.Nil(t, resp)
        require.Error(t, err)
    })
}

func TestPluginExistanceCheckError(t *testing.T) {
    reqStorage := new(logical.InmemStorage)

    t.Run("Test Role Existance Check Failure", func(t *testing.T) {
        checkFound, exists, err := testRoleExistanceCheck(t, reqStorage, map[string]interface{}{
            "role": TEST_ROLE_NAME})
        require.True(t, checkFound)
        require.False(t, exists)
        require.Nil(t, err)
    })
}

func testRoleList(t *testing.T, s logical.Storage) (*logical.Response, error) {
    t.Helper()
    return minio.Backend().HandleRequest(context.Background(), &logical.Request{
        Operation: logical.ListOperation,
        Path:      "roles/",
        Storage:   s,
    })
}

func testRoleCreateOrUpdate(t *testing.T, s logical.Storage, roleName string, d map[string]interface{}) (*logical.Response, error) {
    t.Helper()
    return minio.Backend().HandleRequest(context.Background(), &logical.Request{
        Operation: logical.UpdateOperation,
        Path:      "roles/" + roleName,
        Data:      d,
        Storage:   s,
    })
}

func testRoleRead(t *testing.T, s logical.Storage, roleName string) (*logical.Response, error) {
    t.Helper()
    return minio.Backend().HandleRequest(context.Background(), &logical.Request{
        Operation: logical.ReadOperation,
        Path:      "roles/" + roleName,
        Storage:   s,
    })
}

func testRoleDelete(t *testing.T, s logical.Storage, roleName string) (*logical.Response, error) {
    t.Helper()
    return minio.Backend().HandleRequest(context.Background(), &logical.Request{
        Operation: logical.DeleteOperation,
        Path:      "roles/" + roleName,
        Storage:   s,
    })
}

func testRoleExistanceCheck(t *testing.T, s logical.Storage, d map[string]interface{}) (checkFound bool, exists bool, err error) {
    t.Helper()
    return minio.Backend().HandleExistenceCheck(context.Background(), &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "roles/" + d["role"].(string),
        Data:      d,
        Storage:   s,
    })
}
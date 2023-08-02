/*
 *
 * Nextcloud Android client application
 *
 * @author Tobias Kaminsky
 * Copyright (C) 2023 Tobias Kaminsky
 * Copyright (C) 2023 Nextcloud GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package com.owncloud.android.utils

import com.google.gson.reflect.TypeToken
import com.nextcloud.client.account.MockUser
import com.nextcloud.common.User
import com.owncloud.android.AbstractIT
import com.owncloud.android.datamodel.OCFile
import com.owncloud.android.datamodel.e2e.v1.decrypted.Data
import com.owncloud.android.datamodel.e2e.v1.decrypted.DecryptedFolderMetadataFileV1
import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedFile
import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedFolderMetadataFile
import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedMetadata
import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedUser
import com.owncloud.android.datamodel.e2e.v2.encrypted.EncryptedFolderMetadataFile
import com.owncloud.android.lib.resources.status.E2EVersion
import com.owncloud.android.util.EncryptionTestIT
import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertTrue
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class EncryptionUtilsV2IT : AbstractIT() {
    private val enc1UserId = "enc1"
    private val enc1PrivateKey = """
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAo
        IBAQDsn0JKS/THu328z1IgN0VzYU53HjSX03WJIgWkmyTaxbiKpoJaKbksXmfSpgzV
        GzKFvGfZ03fwFrN7Q8P8R2e8SNiell7mh1TDw9/0P7Bt/ER8PJrXORo+GviKHxaLr7
        Y0BJX9i/nW/L0L/VaE8CZTAqYBdcSJGgHJjY4UMf892ZPTa9T2Dl3ggdMZ7BQ2kiCi
        CC3qV99b0igRJGmmLQaGiAflhFzuDQPMifUMq75wI8RSRPdxUAtjTfkl68QHu7Umye
        yy33OQgdUKaTl5zcS3VSQbNjveVCNM4RDH1RlEc+7Wf1BY8APqT6jbiBcROJD2CeoL
        H2eiIJCi+61ZkSGfAgMBAAECggEBALFStCHrhBf+GL9a+qer4/8QZ/X6i91PmaBX/7
        SYk2jjjWVSXRNmex+V6+Y/jBRT2mvAgm8J+7LPwFdatE+lz0aZrMRD2gCWYF6Itpda
        90OlLkmQPVWWtGTgX2ta2tF5r2iSGzk0IdoL8zw98Q2UzpOcw30KnWtFMxuxWk0mHq
        pgp00g80cDWg3+RPbWOhdLp5bflQ36fKDfmjq05cGlIk6unnVyC5HXpvh4d4k2EWlX
        rjGsndVBPCjGkZePlLRgDHxT06r+5XdJ+1CBDZgCsmjGz3M8uOHyCfVW0WhB7ynzDT
        agVgz0iqpuhAi9sPt6iWWwpAnRw8cQgqEKw9bvKKECgYEA/WPi2PJtL6u/xlysh/H7
        A717CId6fPHCMDace39ZNtzUzc0nT5BemlcF0wZ74NeJSur3Q395YzB+eBMLs5p8mA
        95wgGvJhM65/J+HX+k9kt6Z556zLMvtG+j1yo4D0VEwm3xahB4SUUP+1kD7dNvo4+8
        xeSCyjzNllvYZZC0DrECgYEA7w8pEqhHHn0a+twkPCZJS+gQTB9Rm+FBNGJqB3XpWs
        TeLUxYRbVGk0iDve+eeeZ41drxcdyWP+WcL34hnrjgI1Fo4mK88saajpwUIYMy6+qM
        LY+jC2NRSBox56eH7nsVYvQQK9eKqv9wbB+PF9SwOIvuETN7fd8mAY02UnoaaU8CgY
        BoHRKocXPLkpZJuuppMVQiRUi4SHJbxDo19Tp2w+y0TihiJ1lvp7I3WGpcOt3LlMQk
        tEbExSvrRZGxZKH6Og/XqwQsYuTEkEIz679F/5yYVosE6GkskrOXQAfh8Mb3/04xVV
        tMaVgDQw0+CWVD4wyL+BNofGwBDNqsXTCdCsfxAQKBgQCDv2EtbRw0y1HRKv21QIxo
        ju5cZW4+cDfVPN+eWPdQFOs1H7wOPsc0aGRiiupV2BSEF3O1ApKziEE5U1QH+29bR4
        R8L1pemeGX8qCNj5bCubKjcWOz5PpouDcEqimZ3q98p3E6GEHN15UHoaTkx0yO/V8o
        j6zhQ9fYRxDHB5ACtQKBgQCOO7TJUO1IaLTjcrwS4oCfJyRnAdz49L1AbVJkIBK0fh
        JLecOFu3ZlQl/RStQb69QKb5MNOIMmQhg8WOxZxHcpmIDbkDAm/J/ovJXFSoBdOr5o
        uQsYsDZhsWW97zvLMzg5pH9/3/1BNz5q3Vu4HgfBSwWGt4E2NENj+XA+QAVmGA==
    """.trimIndent()

    private val enc1Cert = """
        -----BEGIN CERTIFICATE-----
        MIIDpzCCAo+gAwIBAgIBADANBgkqhkiG9w0BAQUFADBuMRowGAYDVQQDDBF3d3cu
        bmV4dGNsb3VkLmNvbTESMBAGA1UECgwJTmV4dGNsb3VkMRIwEAYDVQQHDAlTdHV0
        dGdhcnQxGzAZBgNVBAgMEkJhZGVuLVd1ZXJ0dGVtYmVyZzELMAkGA1UEBhMCREUw
        HhcNMTcwOTI2MTAwNDMwWhcNMzcwOTIxMTAwNDMwWjBuMRowGAYDVQQDDBF3d3cu
        bmV4dGNsb3VkLmNvbTESMBAGA1UECgwJTmV4dGNsb3VkMRIwEAYDVQQHDAlTdHV0
        dGdhcnQxGzAZBgNVBAgMEkJhZGVuLVd1ZXJ0dGVtYmVyZzELMAkGA1UEBhMCREUw
        ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsn0JKS/THu328z1IgN0Vz
        YU53HjSX03WJIgWkmyTaxbiKpoJaKbksXmfSpgzVGzKFvGfZ03fwFrN7Q8P8R2e8
        SNiell7mh1TDw9/0P7Bt/ER8PJrXORo+GviKHxaLr7Y0BJX9i/nW/L0L/VaE8CZT
        AqYBdcSJGgHJjY4UMf892ZPTa9T2Dl3ggdMZ7BQ2kiCiCC3qV99b0igRJGmmLQaG
        iAflhFzuDQPMifUMq75wI8RSRPdxUAtjTfkl68QHu7Umyeyy33OQgdUKaTl5zcS3
        VSQbNjveVCNM4RDH1RlEc+7Wf1BY8APqT6jbiBcROJD2CeoLH2eiIJCi+61ZkSGf
        AgMBAAGjUDBOMB0GA1UdDgQWBBTFrXz2tk1HivD9rQ75qeoyHrAgIjAfBgNVHSME
        GDAWgBTFrXz2tk1HivD9rQ75qeoyHrAgIjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
        DQEBBQUAA4IBAQARQTX21QKO77gAzBszFJ6xVnjfa23YZF26Z4X1KaM8uV8TGzuN
        JA95XmReeP2iO3r8EWXS9djVCD64m2xx6FOsrUI8HZaw1JErU8mmOaLAe8q9RsOm
        9Eq37e4vFp2YUEInYUqs87ByUcA4/8g3lEYeIUnRsRsWsA45S3wD7wy07t+KAn7j
        yMmfxdma6hFfG9iN/egN6QXUAyIPXvUvlUuZ7/BhWBj/3sHMrF9quy9Q2DOI8F3t
        1wdQrkq4BtStKhciY5AIXz9SqsctFHTv4Lwgtkapoel4izJnO0ZqYTXVe7THwri9
        H/gua6uJDWH9jk2/CiZDWfsyFuNUuXvDSp05
        -----END CERTIFICATE-----
    """.trimIndent()

    private val enc2Cert = """
        -----BEGIN CERTIFICATE-----
        MIIC7DCCAdSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDDARlbmMz
        MB4XDTIwMDcwODA3MzE1OFoXDTQwMDcwMzA3MzE1OFowDzENMAsGA1UEAwwEZW5j
        MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI/83eC/EF3xOocwjO+Z
        ZkPc1TFxt3aUgjEvrpZu45LOqesG67kkkVDYgjeg3Biz9XRUQXqtXaAyxRZH8GiH
        PFyKUiP1bUlCptd8X+hk9vxeN25YS5OS2RrxU9tDQ/dVOHr20427UvVCighotQnR
        /6+md1FQMV92PFxji7OP5TWOE1y389X6eb7kSPLs8Tu+2PpqaNVQ9C/89Y8KNYWs
        x9Zo+kbQhjfFFUikEpkuzMgT9QLaeq6xuXIPP+y1tzNmF6NTL0a2GoYULuxYWnCe
        joFyXj77LuLmK+KXfPdhvlxa5Kl9XHSxKPHBVVQpwPqNMT+b2T1VLE2l7M9NfImy
        iLcCAwEAAaNTMFEwHQYDVR0OBBYEFBKubDeR2lXwuyTrdyv6O7euPS4PMB8GA1Ud
        IwQYMBaAFBKubDeR2lXwuyTrdyv6O7euPS4PMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
        KoZIhvcNAQEFBQADggEBAChCOIH8CkEpm1eqjsuuNPa93aduLjtnZXat5eIKsKCl
        rL9nFslpg/DO5SeU5ynPY9F2QjX5CN/3RxDXum9vFfpXhTJphOv8N0uHU4ucmQxE
        DN388Vt5VtN3V2pzNUL3JSiG6qeYG047/r/zhGFVpcgb2465G5mEwFT0qnkEseCC
        VVZ63GN8hZgUobyRXxMIhkfWlbO1dgABB4VNyudq0CW8urmewkkbUBwCslvtUvPM
        WuzpQjq2A80bvbrAqO5VUfvMcqRiUWkDgfa6cHXyV0o4N11mMIoxsMgh+PFYr6lR
        BHkuQHqKEwP8kkWugIFj3TMcy9dYtXfMXWvzFaDoE4s=
        -----END CERTIFICATE-----
    """.trimIndent()

    private val enc2PrivateKey = """
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCP/N3gvxBd8TqH
        MIzvmWZD3NUxcbd2lIIxL66WbuOSzqnrBuu5JJFQ2II3oNwYs/V0VEF6rV2gMsUW
        R/BohzxcilIj9W1JQqbXfF/oZPb8XjduWEuTktka8VPbQ0P3VTh69tONu1L1QooI
        aLUJ0f+vpndRUDFfdjxcY4uzj+U1jhNct/PV+nm+5Ejy7PE7vtj6amjVUPQv/PWP
        CjWFrMfWaPpG0IY3xRVIpBKZLszIE/UC2nqusblyDz/stbczZhejUy9GthqGFC7s
        WFpwno6Bcl4++y7i5ivil3z3Yb5cWuSpfVx0sSjxwVVUKcD6jTE/m9k9VSxNpezP
        TXyJsoi3AgMBAAECggEACWwKFtlZ2FPfORZ3unwGwZ0TRFOFJljMdiyBF6307Vfh
        rZP729clPS2Vw88eZ+1qu+yBhmYO0NtRo0Yc2LI0xHd2rYyzVI5sfYBRhFMLCHOf
        2/QiKet7knRFQP1TVr14Xy+Eo2slIBB1GNzFL/nSaeuSNjtxp6YEiCUpcJwTayAi
        Squ5QWMxhlciLKvwUkraFRBqkugvMz3jXzuk/i+DcYlOgoj+tytweNn/azOMH9MH
        mWI+3owYspjzE1rVpbrcWImvlnbInd0z9KaQPpBf7Njj7wtyBMaYww4K4GCMhboD
        SQCYgpnznWkPIN3jyXtmNVSsZ1nvD+Laod+0p7giOQKBgQDA6KEKctYpbt051yTe
        2UP8hpq+MUSS7FIXiHlUc8s0PSujouypUyzfrPeL6yquI0GtKHkMVCWwfT+otMZR
        VnklofrmPTPovvsUQFM4Di411NZwzfxEbBFyVXAUWcLd9NxJ1hZW7w+hLk/N5Bej
        DOa2CncZmifyMNIlvIn7T1vDyQKBgQC/FE8HaDBoN98m/3rEjx7/rVtX8dCei5By
        Fzg/yQ2u4ELbf/Qk/n4k75sy0690EwnFdJxVn2gdNgS1YDv8YP/N5Wfq8xnX9V9B
        irWY/W24cN2qDNXm5i8o5wklyt+fDVqMcEHFfONUpLC+RYmOdc1rrFxPaQOYYYpp
        dWsnuG0ofwKBgBm6rUf8ew35qG3/gP5sEgJLXbZCUfgapvRWkoAuFYs5IWno4BHR
        cym+IyI5Um75atgSjtqTGpfIjMYOnmjY1L2tNg6hWRwQ5OIVlkPiuE0bvyI6hwwF
        MeqC9LjyI+iAsSTz9fTQW9BOofw/ENwBa4AaMzpp8iv+UPkRhYHMWtvpAoGAX6As
        RMqxnxaHCR9GM2Rk4RPC6OpNu2qhKVfRgKp/vIrjKrKIXpM2UgnPo8oovnBgrX7E
        Vl1mX2gPRy4YFx/8JPCv5vcucdOMjmJ6q0v5QxrI9DdkPR/pbhDhlRZIf3LRZAMy
        B0GPC2c4RKDMTI1L9pzVvbASaoo2GLz4mXJEvsUCgYEAibwFNXz1H52sZtL6/1zQ
        1rHCTS8qkryBhxl5eYa6MV5YkbLJZZstF0w2nLxkPba8NttS/nJqjX/iJobD5uLb
        UzeD8jMeAWPNt4DZCtA4ossNYcXIMKqBVFKOANMvAAvLMpVdlNYSucNnTSQcLwI6
        2J9mW5WvAAaG+j28Q/GKSuE=
    """.trimIndent()

    private val t1PrivateKey =
        "MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQC1p8eYMFwGoi7geYzEwNbePRLL5LRhorAecFG3zkpLBwSi/QHkU4u4uSegEbHgOfe73eKVOFdfFpw8wd5cvtY+4CzbX8bu+yrC+tFGcJ25/4VQ78Bl4MI0SvOmxDwuZNrg9SWgs9RwialKOsfCEyz0SS8RstGNt5KZKn1e8z7V9X/eORPmOQ5KcIXHlMbAY3m4erBSKvhRZdqy+Dbnc0rZeZaKkoIMJH1OYfVto/ek12iIKF2YStPVzoTgNsFelPDxeA/lltgf6qDVRD+ELydEncPIJwcv52D8ZitoEyEOfjDZW+rvvE02g1ZD1xPkDLpwltAsFCglCKvKBAWuhthFAgMBAAECgf8BN1MLcq+6m8C1tzNvN/UDd9c0rUpexM6D5eC4O+6B7YGidEqIhHVIzUj0e2HUgpRBbURxsvF1FWdIT2gu7dnULtOGWQxNujJ0kGwXfAnqxh/rACDFb5TS3sJawEExC5yJw14bCEbE/0uBF5uiTU/U9AV7PKHlqAKsS2RtcwPNceB8zDu0hh/Mb/uS7274TsxUllx0WzGZrozO1K6AlOete9rXmmpghpFTNVhxgf0pxe3hrK+tZGSL9di+Wft9eCvSbdG/FzeXgwVqmGtWU7kSB7FqstEEJO4VpOSyEfcXGHTHwdZjrhBUuAcjWE8E0mCKa8htRE52czb3C0f7ZYkCgYEA5eH3vmHEgQjXzSSEtbmDLRq9X9SB7pIAIXHj2UuEOTkLUJ/7xLTHqt82jqZaZzns1RZIJXKZjH85CswQp/py2/qD240KvA/N+ELZaciaV+Wg+m4+iHdi0DyPkaKaBtFG1nsR2GbVWO1OsaTUZTG4D7RCUErU6XVmNPQKSk5uRA0CgYEAykskpX3KKuWq5nxV4vwgPmxz+uAfCtaGhcPEUg764SR+n0ODAvGiEJU7B0Q2oX621pDOQeRfFufiMWfD8ByhErs1HFCmW69YPlR8qamfc8tHG5UM+r3bb49sDEYU4qr1Ji5Zzs4XgfmToKLbWdzzhaW6YxqO7NntIIh2169PPxkCgYBF2TAWl8xGTLKNcYAlW1XBObO6z24fWBtUDi/mEWz+mheXCtVMAoX8pFAGbgNgBBiy8k8/mZ+QMgPaBQE2mQGXV3oDFsrhM4go298Fpl9HP8126lJz0pqinRQecyKL2cDFYKWedDh1Cb30ehnTGZVMqD/R97rTqMlCY7hQtZ4JbQKBgEXpLDQJQeoLT0GybJgyXA5WuspT1EaRlxH5cwqM5MUUMLJnyYol6cVjXXAIcfzj5tpGVxHMk9Q9tR0v6DY+HqhzjEpJ0QRUl+GKnz6fQVzqPpvYqhCptoFahpPDUIp5XJmiYSUoclVX5F4aikYHJx3kBYMkdYqDUgDxSGkHzBJZAoGAHV44xgTW02dgeB5GfDJVWCJKAUGsYOFuUehKUBXSJ0929hdP0sjOQDJN3DEDISzmgdWX5NyLJxEYgFWNivpePjWCWzOzyua3nPSpvxPIUB7xh27gjT91glj1hEmysCd7+9yoMPiCXR7iigRycxegI/Krd39QzISSk9O0finfytU="

    private val t1PublicKey = """-----BEGIN CERTIFICATE-----
MIIC6DCCAdCgAwIBAgIBADANBgkqhkiG9w0BAQUFADANMQswCQYDVQQDDAJ0MTAe
Fw0yMzA3MjUwNzU3MTJaFw00MzA3MjAwNzU3MTJaMA0xCzAJBgNVBAMMAnQxMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtafHmDBcBqIu4HmMxMDW3j0S
y+S0YaKwHnBRt85KSwcEov0B5FOLuLknoBGx4Dn3u93ilThXXxacPMHeXL7WPuAs
21/G7vsqwvrRRnCduf+FUO/AZeDCNErzpsQ8LmTa4PUloLPUcImpSjrHwhMs9Ekv
EbLRjbeSmSp9XvM+1fV/3jkT5jkOSnCFx5TGwGN5uHqwUir4UWXasvg253NK2XmW
ipKCDCR9TmH1baP3pNdoiChdmErT1c6E4DbBXpTw8XgP5ZbYH+qg1UQ/hC8nRJ3D
yCcHL+dg/GYraBMhDn4w2Vvq77xNNoNWQ9cT5Ay6cJbQLBQoJQirygQFrobYRQID
AQABo1MwUTAdBgNVHQ4EFgQUE9zCeA9/QMAtVgLxD23X6ZcodhMwHwYDVR0jBBgw
FoAUE9zCeA9/QMAtVgLxD23X6ZcodhMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQUFAAOCAQEAZdy/YjJlvnz3FQwxp6oVtMJccpdxveEPfLzgaverhtd/vP8O
AvDzOLgQJHmrDS91SG503eU4cYGyuNKwd77OyTnqMg+GUEmJhGfPpSVrEIdh65jv
q61T4oqBdehevVmBq54rGiwL0DGv1DlXQlwiJZP4qni2KnOEFcnvL3gVtRnQjXQ+
kHvlMshkK6w021EMV5NfjG2zg67wC65rLaej5f6Ssp2S7g2VtmE4aXq1bjAuEbqk
4TiyZHLDdsJuqzyGyyOpMV7i9ucXDoaZt9cGS9hT2vRxTrSH63vKR8Xeig9+stLw
t9ONcUqCKP7hd8rajtxM4JIIRExwD8OkgARWGg==
-----END CERTIFICATE-----"""

    @Test
    fun testEncryptDecryptMetadata() {
        val encryptionUtilsV2 = EncryptionUtilsV2()
        val metadataKey = EncryptionUtils.generateKeyString()

        val metadata = DecryptedMetadata(
            mutableListOf("hash1", "hash of key 2"),
            false,
            1,
            mutableMapOf(
                Pair(EncryptionUtils.generateUid(), "Folder 1"),
                Pair(EncryptionUtils.generateUid(), "Folder 2"),
                Pair(EncryptionUtils.generateUid(), "Folder 3")
            ),
            mutableMapOf(
                Pair(
                    EncryptionUtils.generateUid(),
                    DecryptedFile(
                        "file 1.png",
                        "image/png",
                        "initializationVector",
                        "authenticationTag",
                        "key 1"
                    )
                ),
                Pair(
                    EncryptionUtils.generateUid(),
                    DecryptedFile(
                        "file 2.png",
                        "image/png",
                        "initializationVector 2",
                        "authenticationTag 2",
                        "key 2"
                    )
                )
            ),
            metadataKey
        )
        val encrypted = encryptionUtilsV2.encryptMetadata(metadata, metadataKey)
        val decrypted = encryptionUtilsV2.decryptMetadata(encrypted, metadataKey)

        assertEquals(metadata, decrypted)
    }

    @Test
    fun temp() {
        val string = "123"
        val metadataKey = EncryptionUtils.generateKeyString()

        val e = EncryptionUtils.encryptStringSymmetricAsString(
            string,
            metadataKey.toByteArray()
        )

        val d = EncryptionUtils.decryptStringSymmetric(e, metadataKey.toByteArray())
        assertEquals(string, d)

        val encryptedMetadata = EncryptionUtils.encryptStringSymmetric(
            string,
            metadataKey.toByteArray(),
            EncryptionUtils.ivDelimiter
        )

        val d2 = EncryptionUtils.decryptStringSymmetric(
            encryptedMetadata.ciphertext,
            metadataKey.toByteArray()
        )
        assertEquals(string, d2)

        val decrypted = EncryptionUtils.decryptStringSymmetric(
            encryptedMetadata.ciphertext,
            metadataKey.toByteArray(),
            encryptedMetadata.authenticationTag,
            encryptedMetadata.nonce
        )

        assertEquals(string, EncryptionUtils.decodeBase64BytesToString(decrypted))
    }

    @Test
    fun testEncryptDecryptUser() {
        val encryptionUtilsV2 = EncryptionUtilsV2()
        val metadataKey = EncryptionUtils.generateKeyString() // base64
        val user = DecryptedUser("t1", t1PublicKey)

        val encryptedUser = encryptionUtilsV2.encryptUser(user, metadataKey)
        assertNotEquals(encryptedUser.encryptedMetadataKey, metadataKey)

        val decryptedMetadataKey = encryptionUtilsV2.decryptMetadataKey(encryptedUser, t1PrivateKey)

        assertEquals(metadataKey, decryptedMetadataKey)
    }

    @Test
    fun testEncryptDecryptMetadataFile() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val folder = OCFile("/enc")
        val metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)

        val encrypted = encryptionUtilsV2.encryptFolderMetadataFile(
            metadataFile,
            folder,
            storageManager,
            client,
            client.userId,
            enc1PrivateKey,
            enc1Cert
        )
        val decrypted = encryptionUtilsV2.decryptFolderMetadataFile(
            encrypted,
            enc1.accountName,
            enc1PrivateKey,
            folder,
            storageManager,
            client
        )

        assertEquals(metadataFile, decrypted)
    }

    @Test
    fun addFile() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        assertEquals(2, metadataFile.metadata.files.size)
        assertEquals(0, metadataFile.metadata.counter)

        val updatedMetadata = encryptionUtilsV2.addFileToMetadata(
            EncryptionUtils.generateUid(),
            OCFile("/test.jpg").apply {
                mimeType = MimeType.JPEG
            },
            EncryptionUtils.generateIV(),
            EncryptionUtils.generateUid(), // random string, not real tag,
            EncryptionUtils.generateKey(),
            metadataFile
        )

        assertEquals(3, updatedMetadata.metadata.files.size)
        assertEquals(1, updatedMetadata.metadata.counter)
    }

    @Test
    fun removeFile() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        assertEquals(2, metadataFile.metadata.files.size)

        val filename = metadataFile.metadata.files.keys.first()

        encryptionUtilsV2.removeFileFromMetadata(filename, metadataFile)

        assertEquals(1, metadataFile.metadata.files.size)
    }

    @Test
    fun renameFile() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        assertEquals(2, metadataFile.metadata.files.size)

        val key = metadataFile.metadata.files.keys.first()
        val decryptedFile = metadataFile.metadata.files[key]
        val filename = decryptedFile?.filename
        val newFilename = "New File 1"

        encryptionUtilsV2.renameFile(key, newFilename, metadataFile)

        assertEquals(newFilename, metadataFile.metadata.files[key]?.filename)
        assertNotEquals(filename, newFilename)
        assertNotEquals(filename, metadataFile.metadata.files[key]?.filename)
    }

    @Test
    fun addFolder() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        assertEquals(2, metadataFile.metadata.files.size)
        assertEquals(3, metadataFile.metadata.folders.size)

        val updatedMetadata = encryptionUtilsV2.addFolderToMetadata(
            EncryptionUtils.generateUid(),
            "new subfolder",
            metadataFile
        )

        assertEquals(2, updatedMetadata.metadata.files.size)
        assertEquals(4, updatedMetadata.metadata.folders.size)
    }

    @Test
    fun removeFolder() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        assertEquals(2, metadataFile.metadata.files.size)
        assertEquals(3, metadataFile.metadata.folders.size)

        val encryptedFileName = EncryptionUtils.generateUid()
        var updatedMetadata = encryptionUtilsV2.addFolderToMetadata(
            encryptedFileName,
            "new subfolder",
            metadataFile
        )

        assertEquals(2, updatedMetadata.metadata.files.size)
        assertEquals(4, updatedMetadata.metadata.folders.size)

        updatedMetadata = encryptionUtilsV2.removeFolderFromMetadata(
            encryptedFileName,
            updatedMetadata
        )

        assertEquals(2, updatedMetadata.metadata.files.size)
        assertEquals(3, updatedMetadata.metadata.folders.size)
    }

    @Test
    fun signMetadata() {
        throw NotImplementedError()
    }

    @Test
    fun verifyMetadata() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)

        assertTrue(encryptionUtilsV2.verifyMetadata(metadataFile, 0, ""))
    }

    private fun generateDecryptedFileV1(): com.owncloud.android.datamodel.e2e.v1.decrypted.DecryptedFile {
        return com.owncloud.android.datamodel.e2e.v1.decrypted.DecryptedFile().apply {
            encrypted = Data().apply {
                key = EncryptionUtils.generateKeyString()
                filename = "Random filename.jpg"
                mimetype = MimeType.JPEG
                version = 1
            }
            initializationVector = EncryptionUtils.generateKeyString()
            authenticationTag = EncryptionUtils.generateKeyString()
        }
    }

    @Test
    fun testMigrateDecryptedV1ToV2() {
        val v1 = generateDecryptedFileV1()
        val v2 = EncryptionUtilsV2().migrateDecryptedFileV1ToV2(v1)

        assertEquals(v1.encrypted.filename, v2.filename)
        assertEquals(v1.encrypted.mimetype, v2.mimetype)
        assertEquals(v1.authenticationTag, v2.authenticationTag)
        assertEquals(v1.initializationVector, v2.nonce)
        assertEquals(v1.encrypted.key, v2.key)
    }

    @Test
    fun testMigrateMetadataV1ToV2() {
        val v1 = DecryptedFolderMetadataFileV1().apply {
            metadata = com.owncloud.android.datamodel.e2e.v1.decrypted.DecryptedMetadata().apply {
                metadataKeys = mapOf(Pair(0, EncryptionUtils.generateKeyString()))
            }
            files = mapOf(
                Pair(EncryptionUtils.generateUid(), generateDecryptedFileV1()),
                Pair(EncryptionUtils.generateUid(), generateDecryptedFileV1()),
                Pair(
                    EncryptionUtils.generateUid(),
                    com.owncloud.android.datamodel.e2e.v1.decrypted.DecryptedFile().apply {
                        encrypted = Data().apply {
                            key = EncryptionUtils.generateKeyString()
                            filename = "subFolder"
                            mimetype = MimeType.WEBDAV_FOLDER
                        }
                        initializationVector = EncryptionUtils.generateKeyString()
                        authenticationTag = null
                    }
                )
            )
        }
        val v2 = EncryptionUtilsV2().migrateV1ToV2(v1, enc1UserId, enc1Cert)

        assertEquals(v1.files.size, v2.metadata.files.size)
        assertEquals(1, v2.users.size) // only one user upon migration
    }

    @Test
    fun addSharee() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val enc2 = MockUser("enc2", "Nextcloud")
        val folder = OCFile("/enc/")
        var metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)

        metadataFile = encryptionUtilsV2.addShareeToMetadata(metadataFile, enc2.accountName, enc2Cert)

        val encryptedMetadataFile = encryptionUtilsV2.encryptFolderMetadataFile(
            metadataFile,
            folder,
            storageManager,
            client,
            client.userId,
            enc1PrivateKey,
            enc1Cert
        )

        val decryptedByEnc1 = encryptionUtilsV2.decryptFolderMetadataFile(
            encryptedMetadataFile,
            enc1.accountName,
            enc1PrivateKey,
            folder,
            storageManager,
            client
        )
        assertEquals(metadataFile.metadata, decryptedByEnc1.metadata)

        val decryptedByEnc2 = encryptionUtilsV2.decryptFolderMetadataFile(
            encryptedMetadataFile,
            enc2.accountName,
            enc2PrivateKey,
            folder,
            storageManager,
            client
        )
        assertEquals(metadataFile.metadata, decryptedByEnc2.metadata)
    }

    @Test
    fun removeSharee() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val enc1 = MockUser("enc1", "Nextcloud")
        val enc2 = MockUser("enc2", "Nextcloud")
        var metadataFile = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        metadataFile = encryptionUtilsV2.addShareeToMetadata(metadataFile, enc2.accountName, enc2Cert)

        assertEquals(2, metadataFile.users.size)

        metadataFile = encryptionUtilsV2.removeShareeFromMetadata(metadataFile, enc2.accountName)

        assertEquals(1, metadataFile.users.size)
    }

    private fun generateDecryptedFolderMetadataFile(user: User, cert: String): DecryptedFolderMetadataFile {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val metadata = DecryptedMetadata(
            mutableListOf("hash1", "hash of key 2"),
            false,
            0,
            mutableMapOf(
                Pair(EncryptionUtils.generateUid(), "Folder 1"),
                Pair(EncryptionUtils.generateUid(), "Folder 2"),
                Pair(EncryptionUtils.generateUid(), "Folder 3")
            ),
            mutableMapOf(
                Pair(
                    EncryptionUtils.generateUid(),
                    DecryptedFile(
                        "file 1.png",
                        "image/png",
                        "initializationVector",
                        "authenticationTag",
                        "key 1"
                    )
                ),
                Pair(
                    EncryptionUtils.generateUid(),
                    DecryptedFile(
                        "file 2.png",
                        "image/png",
                        "initializationVector 2",
                        "authenticationTag 2",
                        "key 2"
                    )
                )
            ),
            EncryptionUtils.generateKeyString()
        )

        val users = mutableListOf(
            DecryptedUser(user.accountName, cert)
        )

        metadata.keyChecksums.add(encryptionUtilsV2.hashMetadataKey(metadata.metadataKey))

        return DecryptedFolderMetadataFile(metadata, users, mutableMapOf())
    }

    @Test
    fun testGZip() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val string = """
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            This is a test.
            It contains linewraps and special characters:
            $$|²›³¥!’‘‘

        """.trimIndent()

        val gzipped = encryptionUtilsV2.gZipCompress(string)

        val result = encryptionUtilsV2.gZipDecompress(gzipped)

        assertEquals(string, result)
    }

    @Test
    fun gunzip() {
        val encryptionUtilsV2 = EncryptionUtilsV2()

        val string = "H4sICNVkD2QAAwArycgsVgCiRIWS1OISPQDD9wZODwAAAA=="
        val decoded = EncryptionUtils.decodeStringToBase64Bytes(string)
        val gunzip = encryptionUtilsV2.gZipDecompress(decoded)

        assertEquals("this is a test.\n", gunzip)
    }

    @Test
    fun validate() {
        // ALEX
        val metadata1 = """{
"metadata": {
"authenticationTag": "zMozev5R09UopLrq7Je1lw==",
"ciphertext": "j0OBtUrEt4IveGiexjmGK7eKEaWrY70ZkteA5KxHDaZT/t2wwGy9j2FPQGpqXnW6OO3iAYPNgwFikI1smnfNvqdxzVDvhavl/IXa9Kg2niWyqK3D9zpz0YD6mDvl0XsOgTNVyGXNVREdWgzGEERCQoyHI1xowt/swe3KCXw+lf+XPF/t1PfHv0DiDVk70AeWGpPPPu6yggAIxB4Az6PEZhaQWweTC0an48l2FHj2MtB2PiMHtW2v7RMuE8Al3PtE4gOA8CMFrB+Npy6rKcFCXOgTZm5bp7q+J1qkhBDbiBYtvdsYujJ52Xa5SifTpEhGeWWLFnLLgPAQ8o6bXcWOyCoYfLfp4Jpft/Y7H8qzHbPewNSyD6maEv+xljjfU7hxibbszz5A4JjMdQy2BDGoTmJx7Mas+g6l6ZuHLVbdmgQOvD3waJBy6rOg0euux0Cn4bB4bIFEF2KvbhdGbY1Uiq9DYa7kEmSEnlcAYaHyroTkDg4ew7ER0vIBBMzKM3r+UdPVKKS66uyXtZc=",
"nonce": "W+lxQJeGq7XAJiGfcDohkg=="
},
"users": [{
"certificate": "-----BEGIN CERTIFICATE-----\nMIIDkDCCAnigAwIBAgIBADANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJERTEb\nMBkGA1UECAwSQmFkZW4tV3VlcnR0ZW1iZXJnMRIwEAYDVQQHDAlTdHV0dGdhcnQx\nEjAQBgNVBAoMCU5leHRjbG91ZDENMAsGA1UEAwwEam9objAeFw0yMzA3MTQwNzM0\nNTZaFw00MzA3MDkwNzM0NTZaMGExCzAJBgNVBAYTAkRFMRswGQYDVQQIDBJCYWRl\nbi1XdWVydHRlbWJlcmcxEjAQBgNVBAcMCVN0dXR0Z2FydDESMBAGA1UECgwJTmV4\ndGNsb3VkMQ0wCwYDVQQDDARqb2huMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEA7j3Er5YahJT0LAnSRLhpqbRo+E1AVnt98rvp3DmEfBHNzNB+DS9IBDkS\nSXM/YtfAci6Tcw8ujVBjrZX/WEmrf8ynQHxYmSaJSnP8uAT306/MceZpdpruEc9/\nS10a7vp54Zbld4NYdmfS71oVFVKgM7c/Vthx+rgu48fuxzbWAvVYLFcx47hz0DJT\nnjz2Za/R68uXpxfz7J9uEXYiqsAs/FobDsLZluT3RyywVRwKBed1EZxUeLIJiyxp\nUthhGfIb8b3Vf9jZoUVi3m5gmc4spJQHvYAkfZYHzd9ras8jBu1abQRxcu2CYnVo\n6Y0mTxhKhQS/n5gjv3ExiQF3wp/XYwIDAQABo1MwUTAdBgNVHQ4EFgQUmTeILVuB\ntv70fTGkXWGAueDp5kAwHwYDVR0jBBgwFoAUmTeILVuBtv70fTGkXWGAueDp5kAw\nDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAyVtq9XAvW7nxSW/8\nhp30z6xbzGiuviXhy/Jo91VEa8IRsWCCn3OmDFiVduTEowx76tf8clJP0gk7Pozi\n6dg/7Fin+FqQGXfCk8bLAh9gXKAikQ2GK8yRN3slRFwYC2mm23HrLdKXZHUqJcpB\nMz2zsSrOGPj1YsYOl/U8FU6KA7Yj7U3q7kDMYTAgzUPZAH+d1DISGWpZsMa0RYid\nvigCCLByiccmS/Co4Sb1esF58H+YtV5+nFBRwx881U2g2TgDKF1lPMK/y3d8B8mh\nUtW+lFxRpvyNUDpsMjOErOrtNFEYbgoUJLtqwBMmyGR+nmmh6xna331QWcRAmw0P\nnDO4ew==\n-----END CERTIFICATE-----\n",
"encryptedMetadataKey": "HVT49bYmwXbGs/dJ2avgU9unrKnPf03MYUI5ZysSR1Bz5pqz64gzH2GBAuUJ+Q4VmHtEfcMaWW7VXgzfCQv5xLBrk+RSgcLOKnlIya8jaDlfttWxbe8jJK+/0+QVPOc6ycA/t5HNCPg09hzj+gnb2L89UHxL5accZD0iEzb5cQbGrc/N6GthjgGrgFKtFf0HhDVplUr+DL9aTyKuKLBPjrjuZbv8M6ZfXO93mOMwSZH3c3rwDUHb/KEaTR/Og4pWQmrqr1VxGLqeV/+GKWhzMYThrOZAUz+5gsbckU2M5V9i+ph0yBI5BjOZVhNuDwW8yP8WtyRJwQc+UBRei/RGBQ==",
"userId": "john"
}],
"version": "2"
}

"""

        val signature1 =
            "ewogICAgIm1ldGFkYXRhIjogewogICAgICAgICJhdXRoZW50aWNhdGlvblRhZyI6ICJ6TW96ZXY1UjA5VW9wTHJxN0plMWx3PT0iLAogICAgICAgICJjaXBoZXJ0ZXh0IjogImowT0J0VXJFdDRJdmVHaWV4am1HSzdlS0VhV3JZNzBaa3RlQTVLeEhEYVpUL3Qyd3dHeTlqMkZQUUdwcVhuVzZPTzNpQVlQTmd3RmlrSTFzbW5mTnZxZHh6VkR2aGF2bC9JWGE5S2cybmlXeXFLM0Q5enB6MFlENm1EdmwwWHNPZ1ROVnlHWE5WUkVkV2d6R0VFUkNRb3lISTF4b3d0L3N3ZTNLQ1h3K2xmK1hQRi90MVBmSHYwRGlEVms3MEFlV0dwUFBQdTZ5Z2dBSXhCNEF6NlBFWmhhUVd3ZVRDMGFuNDhsMkZIajJNdEIyUGlNSHRXMnY3Uk11RThBbDNQdEU0Z09BOENNRnJCK05weTZyS2NGQ1hPZ1RabTVicDdxK0oxcWtoQkRiaUJZdHZkc1l1ako1MlhhNVNpZlRwRWhHZVdXTEZuTExnUEFROG82YlhjV095Q29ZZkxmcDRKcGZ0L1k3SDhxekhiUGV3TlN5RDZtYUV2K3hsampmVTdoeGliYnN6ejVBNEpqTWRReTJCREdvVG1KeDdNYXMrZzZsNlp1SExWYmRtZ1FPdkQzd2FKQnk2ck9nMGV1dXgwQ240YkI0YklGRUYyS3ZiaGRHYlkxVWlxOURZYTdrRW1TRW5sY0FZYUh5cm9Ua0RnNGV3N0VSMHZJQkJNektNM3IrVWRQVktLUzY2dXlYdFpjPSIsCiAgICAgICAgIm5vbmNlIjogIlcrbHhRSmVHcTdYQUppR2ZjRG9oa2c9PSIKICAgIH0sCiAgICAidXNlcnMiOiB7CiAgICAgICAgImNlcnRpZmljYXRlIjogIi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJRGtEQ0NBbmlnQXdJQkFnSUJBREFOQmdrcWhraUc5dzBCQVFVRkFEQmhNUXN3Q1FZRFZRUUdFd0pFUlRFYlxuTUJrR0ExVUVDQXdTUW1Ga1pXNHRWM1ZsY25SMFpXMWlaWEpuTVJJd0VBWURWUVFIREFsVGRIVjBkR2RoY25ReFxuRWpBUUJnTlZCQW9NQ1U1bGVIUmpiRzkxWkRFTk1Bc0dBMVVFQXd3RWFtOW9iakFlRncweU16QTNNVFF3TnpNMFxuTlRaYUZ3MDBNekEzTURrd056TTBOVFphTUdFeEN6QUpCZ05WQkFZVEFrUkZNUnN3R1FZRFZRUUlEQkpDWVdSbFxuYmkxWGRXVnlkSFJsYldKbGNtY3hFakFRQmdOVkJBY01DVk4wZFhSMFoyRnlkREVTTUJBR0ExVUVDZ3dKVG1WNFxuZEdOc2IzVmtNUTB3Q3dZRFZRUUREQVJxYjJodU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQlxuQ2dLQ0FRRUE3ajNFcjVZYWhKVDBMQW5TUkxocHFiUm8rRTFBVm50OThydnAzRG1FZkJITnpOQitEUzlJQkRrU1xuU1hNL1l0ZkFjaTZUY3c4dWpWQmpyWlgvV0VtcmY4eW5RSHhZbVNhSlNuUDh1QVQzMDYvTWNlWnBkcHJ1RWM5L1xuUzEwYTd2cDU0WmJsZDROWWRtZlM3MW9WRlZLZ003Yy9WdGh4K3JndTQ4ZnV4emJXQXZWWUxGY3g0N2h6MERKVFxubmp6MlphL1I2OHVYcHhmejdKOXVFWFlpcXNBcy9Gb2JEc0xabHVUM1J5eXdWUndLQmVkMUVaeFVlTElKaXl4cFxuVXRoaEdmSWI4YjNWZjlqWm9VVmkzbTVnbWM0c3BKUUh2WUFrZlpZSHpkOXJhczhqQnUxYWJRUnhjdTJDWW5Wb1xuNlkwbVR4aEtoUVMvbjVnanYzRXhpUUYzd3AvWFl3SURBUUFCbzFNd1VUQWRCZ05WSFE0RUZnUVVtVGVJTFZ1QlxudHY3MGZUR2tYV0dBdWVEcDVrQXdId1lEVlIwakJCZ3dGb0FVbVRlSUxWdUJ0djcwZlRHa1hXR0F1ZURwNWtBd1xuRHdZRFZSMFRBUUgvQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBeVZ0cTlYQXZXN254U1cvOFxuaHAzMHo2eGJ6R2l1dmlYaHkvSm85MVZFYThJUnNXQ0NuM09tREZpVmR1VEVvd3g3NnRmOGNsSlAwZ2s3UG96aVxuNmRnLzdGaW4rRnFRR1hmQ2s4YkxBaDlnWEtBaWtRMkdLOHlSTjNzbFJGd1lDMm1tMjNIckxkS1haSFVxSmNwQlxuTXoyenNTck9HUGoxWXNZT2wvVThGVTZLQTdZajdVM3E3a0RNWVRBZ3pVUFpBSCtkMURJU0dXcFpzTWEwUllpZFxudmlnQ0NMQnlpY2NtUy9DbzRTYjFlc0Y1OEgrWXRWNStuRkJSd3g4ODFVMmcyVGdES0YxbFBNSy95M2Q4QjhtaFxuVXRXK2xGeFJwdnlOVURwc01qT0VyT3J0TkZFWWJnb1VKTHRxd0JNbXlHUitubW1oNnhuYTMzMVFXY1JBbXcwUFxubkRPNGV3PT1cbi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS1cbiIsCiAgICAgICAgImVuY3J5cHRlZE1ldGFkYXRhS2V5IjogIkhWVDQ5Ylltd1hiR3MvZEoyYXZnVTl1bnJLblBmMDNNWVVJNVp5c1NSMUJ6NXBxejY0Z3pIMkdCQXVVSitRNFZtSHRFZmNNYVdXN1ZYZ3pmQ1F2NXhMQnJrK1JTZ2NMT0tubEl5YThqYURsZnR0V3hiZThqSksrLzArUVZQT2M2eWNBL3Q1SE5DUGcwOWh6aitnbmIyTDg5VUh4TDVhY2NaRDBpRXpiNWNRYkdyYy9ONkd0aGpnR3JnRkt0RmYwSGhEVnBsVXIrREw5YVR5S3VLTEJQanJqdVpidjhNNlpmWE85M21PTXdTWkgzYzNyd0RVSGIvS0VhVFIvT2c0cFdRbXJxcjFWeEdMcWVWLytHS1doek1ZVGhyT1pBVXorNWdzYmNrVTJNNVY5aStwaDB5Qkk1QmpPWlZoTnVEd1c4eVA4V3R5Ukp3UWMrVUJSZWkvUkdCUT09IiwKICAgICAgICAidXNlcklkIjogImpvaG4iCiAgICB9LAogICAgInZlcnNpb24iOiAiMiIKfQo="

        // TOBI
        val metadata =
            """{"metadata":{"authenticationTag":"qDcJnAAGtGDlHWiQMBfXgw\u003d\u003d","ciphertext":"3zUhwIgJWMB7DvrbsDaMvh8MbJdoTxL0OMPCCdYSfBt7gB+V/hwqelL1IOaLto3avhHGSebnrotF06iEP/jZwWg9hApIPTHc8B4XTOY0/kezqYyVqTyquTUZpDpqgVAheQskZZ8I4Ir0seajUkt4KtVRfzO6v8CePRrEg6uKwdYsqDcJnAAGtGDlHWiQMBfXgw\u003d\u003d|4hbOyn1ykQL+9D6SnPY3cQ\u003d\u003d","nonce":"4hbOyn1ykQL+9D6SnPY3cQ\u003d\u003d"},"users":[{"certificate":"-----BEGIN CERTIFICATE-----\nMIIC6DCCAdCgAwIBAgIBADANBgkqhkiG9w0BAQUFADANMQswCQYDVQQDDAJ0MTAe\nFw0yMzA3MjUwNzU3MTJaFw00MzA3MjAwNzU3MTJaMA0xCzAJBgNVBAMMAnQxMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtafHmDBcBqIu4HmMxMDW3j0S\ny+S0YaKwHnBRt85KSwcEov0B5FOLuLknoBGx4Dn3u93ilThXXxacPMHeXL7WPuAs\n21/G7vsqwvrRRnCduf+FUO/AZeDCNErzpsQ8LmTa4PUloLPUcImpSjrHwhMs9Ekv\nEbLRjbeSmSp9XvM+1fV/3jkT5jkOSnCFx5TGwGN5uHqwUir4UWXasvg253NK2XmW\nipKCDCR9TmH1baP3pNdoiChdmErT1c6E4DbBXpTw8XgP5ZbYH+qg1UQ/hC8nRJ3D\nyCcHL+dg/GYraBMhDn4w2Vvq77xNNoNWQ9cT5Ay6cJbQLBQoJQirygQFrobYRQID\nAQABo1MwUTAdBgNVHQ4EFgQUE9zCeA9/QMAtVgLxD23X6ZcodhMwHwYDVR0jBBgw\nFoAUE9zCeA9/QMAtVgLxD23X6ZcodhMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG\n9w0BAQUFAAOCAQEAZdy/YjJlvnz3FQwxp6oVtMJccpdxveEPfLzgaverhtd/vP8O\nAvDzOLgQJHmrDS91SG503eU4cYGyuNKwd77OyTnqMg+GUEmJhGfPpSVrEIdh65jv\nq61T4oqBdehevVmBq54rGiwL0DGv1DlXQlwiJZP4qni2KnOEFcnvL3gVtRnQjXQ+\nkHvlMshkK6w021EMV5NfjG2zg67wC65rLaej5f6Ssp2S7g2VtmE4aXq1bjAuEbqk\n4TiyZHLDdsJuqzyGyyOpMV7i9ucXDoaZt9cGS9hT2vRxTrSH63vKR8Xeig9+stLw\nt9ONcUqCKP7hd8rajtxM4JIIRExwD8OkgARWGg\u003d\u003d\n-----END CERTIFICATE-----\n","encryptedMetadataKey":"s4kDkkLpk1mSmXedP7huiCNC4DYmDAmA2VYGem5M8jIGPC6miVQoo4WXZrEBhdsLw7Msf5iT3A3fTaHhwsI8Jf4McsFyM9/FXT1mCEaGOEpNjbKOlJY1uPUFNOhLqUfFiBos6oBT53hWwoXWjytYvLBbXuXY5YLOysjgBh6URrgFUZAJAmcOJ6OFKgfIIthoqkQc7CQUY97VsRzAXzeYTANBc2yW1pSN51HqftvMzvewFRsJQLcu7a9NjpTdG9LiLhn5eLXOLymXEE/aaPHKXeprlXLzrdWU1xwZRJqV+to2FEiH6CQNsO4+9h5m0VjXekiNeAFrsXB5cJgUipGuzQ\u003d\u003d","userId":"t1"}],"version":"2.0"}"""

        val base = EncryptionUtils.encodeStringToBase64String(metadata)

        val signature =
            "MIAGCSqGSIb3DQEHAqCAMIACAQExDTALBglghkgBZQMEAgEwCwYJKoZIhvcNAQcBoIAwggLoMIIB0KADAgECAgEAMA0GCSqGSIb3DQEBBQUAMA0xCzAJBgNVBAMMAnQxMB4XDTIzMDcyNTA3NTcxMloXDTQzMDcyMDA3NTcxMlowDTELMAkGA1UEAwwCdDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1p8eYMFwGoi7geYzEwNbePRLL5LRhorAecFG3zkpLBwSi/QHkU4u4uSegEbHgOfe73eKVOFdfFpw8wd5cvtY+4CzbX8bu+yrC+tFGcJ25/4VQ78Bl4MI0SvOmxDwuZNrg9SWgs9RwialKOsfCEyz0SS8RstGNt5KZKn1e8z7V9X/eORPmOQ5KcIXHlMbAY3m4erBSKvhRZdqy+Dbnc0rZeZaKkoIMJH1OYfVto/ek12iIKF2YStPVzoTgNsFelPDxeA/lltgf6qDVRD+ELydEncPIJwcv52D8ZitoEyEOfjDZW+rvvE02g1ZD1xPkDLpwltAsFCglCKvKBAWuhthFAgMBAAGjUzBRMB0GA1UdDgQWBBQT3MJ4D39AwC1WAvEPbdfplyh2EzAfBgNVHSMEGDAWgBQT3MJ4D39AwC1WAvEPbdfplyh2EzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBl3L9iMmW+fPcVDDGnqhW0wlxyl3G94Q98vOBq96uG13+8/w4C8PM4uBAkeasNL3VIbnTd5ThxgbK40rB3vs7JOeoyD4ZQSYmEZ8+lJWsQh2HrmO+rrVPiioF16F69WYGrnisaLAvQMa/UOVdCXCIlk/iqeLYqc4QVye8veBW1GdCNdD6Qe+UyyGQrrDTbUQxXk1+MbbODrvALrmstp6Pl/pKynZLuDZW2YThperVuMC4RuqThOLJkcsN2wm6rPIbLI6kxXuL25xcOhpm31wZL2FPa9HFOtIfre8pHxd6KD36y0vC3041xSoIo/uF3ytqO3EzgkghETHAPw6SABFYaAAAxggHUMIIB0AIBATASMA0xCzAJBgNVBAMMAnQxAgEAMAsGCWCGSAFlAwQCAaCBljAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA3MjgwNzMwMTJaMCsGCSqGSIb3DQEJNDEeMBwwCwYJYIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCAx7RTJg7hbY5Mkzjw3f6qhX7k/J0FdVz2cL3ow0AmyYjANBgkqhkiG9w0BAQsFAASCAQAbUmb9e7eoIcPNzDSmnzbrueBzgT8YszNGEI+1YCq8XdWN4kDztvP1ZNV21VCO6BvcbfUAnXXgcX5BPeLZNsgXPj3c8TbD59GQl3oT/tIchgMsA20RdAtIwvItlZKh+X6sp0OHkRPYSk/mEYKCKPqrKdJicRWex8ItCwpDR91KSOiKJrN/+DKOGG0sVI9gjzbtrHsN8HmVKxOoNV+wwipcLsWsEmuV+wvPCQ9HJidLX9Q17Bgfc+qJg19aB6iKLWPhjgnfpKGbK5VJuQTdDWPUJ2O4G3W/iwxJ0hAJ7tks4zIATmgGzhgTWYx5LVXbKcuL04xhIOjqwedHeCSBZSSaAAAAAAAA"

        val metadataFile = EncryptionUtils.deserializeJSON(
            metadata,
            object : TypeToken<EncryptedFolderMetadataFile>() {}
        )
        assertNotNull(metadataFile)

        val certJohnString = metadataFile.users[0].certificate
        val certJohn = EncryptionUtils.convertCertFromString(certJohnString)

        val t1String = """-----BEGIN CERTIFICATE-----
MIIC6DCCAdCgAwIBAgIBADANBgkqhkiG9w0BAQUFADANMQswCQYDVQQDDAJ0MTAe
Fw0yMzA3MjUwNzU3MTJaFw00MzA3MjAwNzU3MTJaMA0xCzAJBgNVBAMMAnQxMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtafHmDBcBqIu4HmMxMDW3j0S
y+S0YaKwHnBRt85KSwcEov0B5FOLuLknoBGx4Dn3u93ilThXXxacPMHeXL7WPuAs
21/G7vsqwvrRRnCduf+FUO/AZeDCNErzpsQ8LmTa4PUloLPUcImpSjrHwhMs9Ekv
EbLRjbeSmSp9XvM+1fV/3jkT5jkOSnCFx5TGwGN5uHqwUir4UWXasvg253NK2XmW
ipKCDCR9TmH1baP3pNdoiChdmErT1c6E4DbBXpTw8XgP5ZbYH+qg1UQ/hC8nRJ3D
yCcHL+dg/GYraBMhDn4w2Vvq77xNNoNWQ9cT5Ay6cJbQLBQoJQirygQFrobYRQID
AQABo1MwUTAdBgNVHQ4EFgQUE9zCeA9/QMAtVgLxD23X6ZcodhMwHwYDVR0jBBgw
FoAUE9zCeA9/QMAtVgLxD23X6ZcodhMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQUFAAOCAQEAZdy/YjJlvnz3FQwxp6oVtMJccpdxveEPfLzgaverhtd/vP8O
AvDzOLgQJHmrDS91SG503eU4cYGyuNKwd77OyTnqMg+GUEmJhGfPpSVrEIdh65jv
q61T4oqBdehevVmBq54rGiwL0DGv1DlXQlwiJZP4qni2KnOEFcnvL3gVtRnQjXQ+
kHvlMshkK6w021EMV5NfjG2zg67wC65rLaej5f6Ssp2S7g2VtmE4aXq1bjAuEbqk
4TiyZHLDdsJuqzyGyyOpMV7i9ucXDoaZt9cGS9hT2vRxTrSH63vKR8Xeig9+stLw
t9ONcUqCKP7hd8rajtxM4JIIRExwD8OkgARWGg==
-----END CERTIFICATE-----"""

        val t1cert = EncryptionUtils.convertCertFromString(t1String)
        val t1PrivateKeyKey = EncryptionUtils.PEMtoPrivateKey(t1PrivateKey)

        // val signed = EncryptionUtilsV2().getMessageSignature(
        //     t1cert,
        //     t1PrivateKeyKey,
        //     metadataFile
        // )

        assertTrue(EncryptionUtilsV2().verifySignedMessage(signature1, metadata1, listOf(certJohn, t1cert)))
    }

    @Test
    fun testSigning() {
        val metadata =
            """{"metadata": {"authenticationTag": "zMozev5R09UopLrq7Je1lw==","ciphertext": "j0OBtUrEt4IveGiexjmGK7eKEaWrY70ZkteA5KxHDaZT/t2wwGy9j2FPQGpqXnW6OO3iAYPNgwFikI1smnfNvqdxzVDvhavl/IXa9Kg2niWyqK3D9zpz0YD6mDvl0XsOgTNVyGXNVREdWgzGEERCQoyHI1xowt/swe3KCXw+lf+XPF/t1PfHv0DiDVk70AeWGpPPPu6yggAIxB4Az6PEZhaQWweTC0an48l2FHj2MtB2PiMHtW2v7RMuE8Al3PtE4gOA8CMFrB+Npy6rKcFCXOgTZm5bp7q+J1qkhBDbiBYtvdsYujJ52Xa5SifTpEhGeWWLFnLLgPAQ8o6bXcWOyCoYfLfp4Jpft/Y7H8qzHbPewNSyD6maEv+xljjfU7hxibbszz5A4JjMdQy2BDGoTmJx7Mas+g6l6ZuHLVbdmgQOvD3waJBy6rOg0euux0Cn4bB4bIFEF2KvbhdGbY1Uiq9DYa7kEmSEnlcAYaHyroTkDg4ew7ER0vIBBMzKM3r+UdPVKKS66uyXtZc=","nonce": "W+lxQJeGq7XAJiGfcDohkg=="},"users": [{"certificate": "-----BEGIN CERTIFICATE-----\nMIIDkDCCAnigAwIBAgIBADANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJERTEb\nMBkGA1UECAwSQmFkZW4tV3VlcnR0ZW1iZXJnMRIwEAYDVQQHDAlTdHV0dGdhcnQx\nEjAQBgNVBAoMCU5leHRjbG91ZDENMAsGA1UEAwwEam9objAeFw0yMzA3MTQwNzM0\nNTZaFw00MzA3MDkwNzM0NTZaMGExCzAJBgNVBAYTAkRFMRswGQYDVQQIDBJCYWRl\nbi1XdWVydHRlbWJlcmcxEjAQBgNVBAcMCVN0dXR0Z2FydDESMBAGA1UECgwJTmV4\ndGNsb3VkMQ0wCwYDVQQDDARqb2huMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEA7j3Er5YahJT0LAnSRLhpqbRo+E1AVnt98rvp3DmEfBHNzNB+DS9IBDkS\nSXM/YtfAci6Tcw8ujVBjrZX/WEmrf8ynQHxYmSaJSnP8uAT306/MceZpdpruEc9/\nS10a7vp54Zbld4NYdmfS71oVFVKgM7c/Vthx+rgu48fuxzbWAvVYLFcx47hz0DJT\nnjz2Za/R68uXpxfz7J9uEXYiqsAs/FobDsLZluT3RyywVRwKBed1EZxUeLIJiyxp\nUthhGfIb8b3Vf9jZoUVi3m5gmc4spJQHvYAkfZYHzd9ras8jBu1abQRxcu2CYnVo\n6Y0mTxhKhQS/n5gjv3ExiQF3wp/XYwIDAQABo1MwUTAdBgNVHQ4EFgQUmTeILVuB\ntv70fTGkXWGAueDp5kAwHwYDVR0jBBgwFoAUmTeILVuBtv70fTGkXWGAueDp5kAw\nDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAyVtq9XAvW7nxSW/8\nhp30z6xbzGiuviXhy/Jo91VEa8IRsWCCn3OmDFiVduTEowx76tf8clJP0gk7Pozi\n6dg/7Fin+FqQGXfCk8bLAh9gXKAikQ2GK8yRN3slRFwYC2mm23HrLdKXZHUqJcpB\nMz2zsSrOGPj1YsYOl/U8FU6KA7Yj7U3q7kDMYTAgzUPZAH+d1DISGWpZsMa0RYid\nvigCCLByiccmS/Co4Sb1esF58H+YtV5+nFBRwx881U2g2TgDKF1lPMK/y3d8B8mh\nUtW+lFxRpvyNUDpsMjOErOrtNFEYbgoUJLtqwBMmyGR+nmmh6xna331QWcRAmw0P\nnDO4ew==\n-----END CERTIFICATE-----\n","encryptedMetadataKey": "HVT49bYmwXbGs/dJ2avgU9unrKnPf03MYUI5ZysSR1Bz5pqz64gzH2GBAuUJ+Q4VmHtEfcMaWW7VXgzfCQv5xLBrk+RSgcLOKnlIya8jaDlfttWxbe8jJK+/0+QVPOc6ycA/t5HNCPg09hzj+gnb2L89UHxL5accZD0iEzb5cQbGrc/N6GthjgGrgFKtFf0HhDVplUr+DL9aTyKuKLBPjrjuZbv8M6ZfXO93mOMwSZH3c3rwDUHb/KEaTR/Og4pWQmrqr1VxGLqeV/+GKWhzMYThrOZAUz+5gsbckU2M5V9i+ph0yBI5BjOZVhNuDwW8yP8WtyRJwQc+UBRei/RGBQ==","userId": "john"}],"version": "2"}"""
        val base64Metadata = EncryptionUtils.encodeStringToBase64String(metadata)

        val encryptionUtilsV2 = EncryptionUtilsV2()

        val privateKey = EncryptionUtils.PEMtoPrivateKey(t1PrivateKey)
        val certificateT1 = EncryptionUtils.convertCertFromString(t1PublicKey)
        val certificateEnc2 = EncryptionUtils.convertCertFromString(enc2Cert)

        val signed = encryptionUtilsV2.signMessage(
            certificateT1,
            privateKey,
            metadata
        )

        val base64Ans = encryptionUtilsV2.extractSignedString(signed)

        // verify
        val certs = listOf(
            certificateEnc2,
            certificateT1
        )
        assertTrue(encryptionUtilsV2.verifySignedMessage(signed, certs))
        assertTrue(encryptionUtilsV2.verifySignedMessage(base64Ans, base64Metadata, certs))
    }

    @Test
    fun sign() {
        val encryptionUtilsV2 = EncryptionUtilsV2()
        val enc1 = MockUser("enc1", "Nextcloud")
        //val sut = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        // val json = EncryptionUtils.serializeJSON(sut, true)

        val sut = "randomstring123"
        val json = "randomstring123"

        val privateKey = EncryptionUtils.PEMtoPrivateKey(t1PrivateKey)
        val certificate = EncryptionUtils.convertCertFromString(t1PublicKey)

        val signed = encryptionUtilsV2.signMessage(
            certificate,
            privateKey,
            sut
        )

        val base64Ans = encryptionUtilsV2.extractSignedString(signed)

        // verify
        val certs = listOf(
            EncryptionUtils.convertCertFromString(enc2Cert),
            certificate
        )
        assertTrue(encryptionUtilsV2.verifySignedMessage(signed, certs))
        assertTrue(encryptionUtilsV2.verifySignedMessage(base64Ans, json, certs))
    }

    @Test
    fun signWindows() {
        val encryptionUtilsV2 = EncryptionUtilsV2()
        val enc1 = MockUser("enc1", "Nextcloud")
        //val sut = generateDecryptedFolderMetadataFile(enc1, enc1Cert)
        // val json = EncryptionUtils.serializeJSON(sut, true)

        val sut = "windowsrandomstring123"
        val json = "windowsrandomstring123"

        val privateKey = EncryptionUtils.PEMtoPrivateKey(t1PrivateKey)
        val certificate = EncryptionUtils.convertCertFromString(t1PublicKey)

        val base64Ans =
            """MIIFSAYJKoZIhvcNAQcCoIIFOTCCBTUCAQExDTALBglghkgBZQMEAgEwCwYJKoZIhvcNAQcBoIIC7DCCAugwggHQoAMCAQICAQAwDQYJKoZIhvcNAQEFBQAwDTELMAkGA1UEAwwCdDEwHhcNMjMwNzI1MDc1NzEyWhcNNDMwNzIwMDc1NzEyWjANMQswCQYDVQQDDAJ0MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALWnx5gwXAaiLuB5jMTA1t49EsvktGGisB5wUbfOSksHBKL9AeRTi7i5J6ARseA597vd4pU4V18WnDzB3ly+1j7gLNtfxu77KsL60UZwnbn/hVDvwGXgwjRK86bEPC5k2uD1JaCz1HCJqUo6x8ITLPRJLxGy0Y23kpkqfV7zPtX1f945E+Y5DkpwhceUxsBjebh6sFIq+FFl2rL4NudzStl5loqSggwkfU5h9W2j96TXaIgoXZhK09XOhOA2wV6U8PF4D+WW2B/qoNVEP4QvJ0Sdw8gnBy/nYPxmK2gTIQ5+MNlb6u+8TTaDVkPXE+QMunCW0CwUKCUIq8oEBa6G2EUCAwEAAaNTMFEwHQYDVR0OBBYEFBPcwngPf0DALVYC8Q9t1+mXKHYTMB8GA1UdIwQYMBaAFBPcwngPf0DALVYC8Q9t1+mXKHYTMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAGXcv2IyZb589xUMMaeqFbTCXHKXcb3hD3y84Gr3q4bXf7z/DgLw8zi4ECR5qw0vdUhudN3lOHGBsrjSsHe+zsk56jIPhlBJiYRnz6UlaxCHYeuY76utU+KKgXXoXr1ZgaueKxosC9Axr9Q5V0JcIiWT+Kp4tipzhBXJ7y94FbUZ0I10PpB75TLIZCusNNtRDFeTX4xts4Ou8Auuay2no+X+krKdku4NlbZhOGl6tW4wLhG6pOE4smRyw3bCbqs8hssjqTFe4vbnFw6GmbfXBkvYU9r0cU60h+t7ykfF3ooPfrLS8LfTjXFKgij+4XfK2o7cTOCSCERMcA/DpIAEVhoxggIiMIICHgIBATASMA0xCzAJBgNVBAMMAnQxAgEAMAsGCWCGSAFlAwQCAaCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMzA3MjgxMjIwMTNaMC8GCSqGSIb3DQEJBDEiBCDKmcDaHONFCK8DWr0lJwfBQdlmVSyyqgzpplVlVIndxzB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQCcaKwRe3TPumGkPEXrOgk4kJuNLrF7GLI+wGwaM8rwOxlfC6mG/Oz+v66WJok2LdvH64wwl/hdJO1n1PYQxVm0FHMntwGKjyuXMdo+VZEbEE6+T36hHTh1y0tDf4Z/DM0/QyEegqqw59+H9crzNMyw8r8xx6dAjiB3zku7QXBN3bkBfeilRELRN5HHUiMAuqXkYMPWQzNcTNC8VCqGMwlHKu6FcXFrnXiqd9O2AidvUI8vp3b4GKQEfhKxyiUzJYyk68+KQA3MaM6ybrWZ126aAUUQ4MdqYTxqHQnG09D9bFpKS7zIrLC7TIUhnkM1PLygLz46ekIIn2IJlsvZ6ZsH"""

        // verify
        val certs = listOf(
            EncryptionUtils.convertCertFromString(enc2Cert),
            certificate
        )
        //assertTrue(encryptionUtilsV2.verifySignedMessage(signed, certs))
        assertTrue(encryptionUtilsV2.verifySignedMessage(base64Ans, json, certs))
    }

    /**
     * DecryptedFolderMetadata -> EncryptedFolderMetadata -> JSON -> encrypt -> decrypt -> JSON ->
     * EncryptedFolderMetadata -> DecryptedFolderMetadata
     */
    @Test
    @Throws(Exception::class)
    fun encryptionMetadataV2() {
        val encryptionUtilsV2 = EncryptionUtilsV2()
        val decryptedFolderMetadata1: DecryptedFolderMetadataFile = generateFolderMetadataV2()
        val root = OCFile("/")
        root.localId = 0
        val folder = OCFile("/enc")
        folder.localId = 1
        folder.parentId = 0

        // TODO re-add filedrop
        decryptedFolderMetadata1.filedrop.clear()

        // encrypt
        val encryptedFolderMetadata1 = encryptionUtilsV2.encryptFolderMetadataFile(
            decryptedFolderMetadata1,
            folder,
            fileDataStorageManager,
            client,
            client.userId,
            EncryptionTestIT.privateKey,
            EncryptionTestIT.publicKey
        )

        // serialize
        val encryptedJson = EncryptionUtils.serializeJSON(encryptedFolderMetadata1)

        // de-serialize
        val encryptedFolderMetadata2 = EncryptionUtils.deserializeJSON(
            encryptedJson,
            object : TypeToken<EncryptedFolderMetadataFile?>() {}
        )

        // decrypt
        val decryptedFolderMetadata2 = EncryptionUtilsV2().decryptFolderMetadataFile(
            encryptedFolderMetadata2!!,
            getUserId(user),
            EncryptionTestIT.privateKey,
            folder,
            fileDataStorageManager,
            client
        )

        // compare
        assertTrue(
            EncryptionTestIT.compareJsonStrings(
                EncryptionUtils.serializeJSON(decryptedFolderMetadata1),
                EncryptionUtils.serializeJSON(decryptedFolderMetadata2)
            )
        )
    }

    @Throws(java.lang.Exception::class)
    private fun generateFolderMetadataV2(): DecryptedFolderMetadataFile {
        var metadataKey = EncryptionUtils.encodeBytesToBase64String(EncryptionUtils.generateKey())
        val encryptedMetadataKey: String =
            EncryptionUtils.encryptStringAsymmetric(metadataKey, EncryptionTestIT.publicKey)

        val metadata = DecryptedMetadata().apply {
            metadataKey = encryptedMetadataKey
        }

        val file1 = DecryptedFile(
            "image1.png",
            "image/png",
            "gKm3n+mJzeY26q4OfuZEqg==",
            "PboI9tqHHX3QeAA22PIu4w==",
            "WANM0gRv+DhaexIsI0T3Lg=="
        )

        val file2 = DecryptedFile(
            "image2.png",
            "image/png",
            "hnJLF8uhDvDoFK4ajuvwrg==",
            "qOQZdu5soFO77Y7y4rAOVA==",
            "9dfzbIYDt28zTyZfbcll+g=="
        )

        val users = mutableListOf(
            DecryptedUser(client.userId, EncryptionTestIT.publicKey)
        )

        val filedrop = mutableMapOf(
            Pair(
                "eie8iaeiaes8e87td6",
                DecryptedFile(
                    "test2.txt",
                    "txt/plain",
                    "hnJLF8uhDvDoFK4ajuvwrg==",
                    "qOQZdu5soFO77Y7y4rAOVA==",
                    "9dfzbIYDt28zTyZfbcll+g=="
                )
            )
        )

        metadata.files["ia7OEEEyXMoRa1QWQk8r"] = file1
        metadata.files["n9WXAIXO2wRY4R8nXwmo"] = file2

        return DecryptedFolderMetadataFile(metadata, users, filedrop, E2EVersion.V2_0.value)
    }
}

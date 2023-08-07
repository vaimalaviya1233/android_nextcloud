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

import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedFile
import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedFolderMetadataFile
import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedMetadata
import com.owncloud.android.datamodel.e2e.v2.decrypted.DecryptedUser
import com.owncloud.android.lib.resources.status.E2EVersion

class EncryptionTestUtils {
    val t1PrivateKey =
        "MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQC1p8eYMFwGoi7geYzEwNbePRLL5LRhorAecFG3zkpLBwSi/QHkU4u4uSegEbHgOfe73eKVOFdfFpw8wd5cvtY+4CzbX8bu+yrC+tFGcJ25/4VQ78Bl4MI0SvOmxDwuZNrg9SWgs9RwialKOsfCEyz0SS8RstGNt5KZKn1e8z7V9X/eORPmOQ5KcIXHlMbAY3m4erBSKvhRZdqy+Dbnc0rZeZaKkoIMJH1OYfVto/ek12iIKF2YStPVzoTgNsFelPDxeA/lltgf6qDVRD+ELydEncPIJwcv52D8ZitoEyEOfjDZW+rvvE02g1ZD1xPkDLpwltAsFCglCKvKBAWuhthFAgMBAAECgf8BN1MLcq+6m8C1tzNvN/UDd9c0rUpexM6D5eC4O+6B7YGidEqIhHVIzUj0e2HUgpRBbURxsvF1FWdIT2gu7dnULtOGWQxNujJ0kGwXfAnqxh/rACDFb5TS3sJawEExC5yJw14bCEbE/0uBF5uiTU/U9AV7PKHlqAKsS2RtcwPNceB8zDu0hh/Mb/uS7274TsxUllx0WzGZrozO1K6AlOete9rXmmpghpFTNVhxgf0pxe3hrK+tZGSL9di+Wft9eCvSbdG/FzeXgwVqmGtWU7kSB7FqstEEJO4VpOSyEfcXGHTHwdZjrhBUuAcjWE8E0mCKa8htRE52czb3C0f7ZYkCgYEA5eH3vmHEgQjXzSSEtbmDLRq9X9SB7pIAIXHj2UuEOTkLUJ/7xLTHqt82jqZaZzns1RZIJXKZjH85CswQp/py2/qD240KvA/N+ELZaciaV+Wg+m4+iHdi0DyPkaKaBtFG1nsR2GbVWO1OsaTUZTG4D7RCUErU6XVmNPQKSk5uRA0CgYEAykskpX3KKuWq5nxV4vwgPmxz+uAfCtaGhcPEUg764SR+n0ODAvGiEJU7B0Q2oX621pDOQeRfFufiMWfD8ByhErs1HFCmW69YPlR8qamfc8tHG5UM+r3bb49sDEYU4qr1Ji5Zzs4XgfmToKLbWdzzhaW6YxqO7NntIIh2169PPxkCgYBF2TAWl8xGTLKNcYAlW1XBObO6z24fWBtUDi/mEWz+mheXCtVMAoX8pFAGbgNgBBiy8k8/mZ+QMgPaBQE2mQGXV3oDFsrhM4go298Fpl9HP8126lJz0pqinRQecyKL2cDFYKWedDh1Cb30ehnTGZVMqD/R97rTqMlCY7hQtZ4JbQKBgEXpLDQJQeoLT0GybJgyXA5WuspT1EaRlxH5cwqM5MUUMLJnyYol6cVjXXAIcfzj5tpGVxHMk9Q9tR0v6DY+HqhzjEpJ0QRUl+GKnz6fQVzqPpvYqhCptoFahpPDUIp5XJmiYSUoclVX5F4aikYHJx3kBYMkdYqDUgDxSGkHzBJZAoGAHV44xgTW02dgeB5GfDJVWCJKAUGsYOFuUehKUBXSJ0929hdP0sjOQDJN3DEDISzmgdWX5NyLJxEYgFWNivpePjWCWzOzyua3nPSpvxPIUB7xh27gjT91glj1hEmysCd7+9yoMPiCXR7iigRycxegI/Krd39QzISSk9O0finfytU="

    val t1PublicKey = """-----BEGIN CERTIFICATE-----
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

    @Throws(java.lang.Exception::class)
    fun generateFolderMetadataV2(userId: String, cert: String): DecryptedFolderMetadataFile {
        var metadataKey = EncryptionUtils.encodeBytesToBase64String(EncryptionUtils.generateKey())
        val encryptedMetadataKey: String =
            EncryptionUtils.encryptStringAsymmetric(metadataKey, cert)

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
            DecryptedUser(userId, cert)
        )

        // val filedrop = mutableMapOf(
        //     Pair(
        //         "eie8iaeiaes8e87td6",
        //         DecryptedFile(
        //             "test2.txt",
        //             "txt/plain",
        //             "hnJLF8uhDvDoFK4ajuvwrg==",
        //             "qOQZdu5soFO77Y7y4rAOVA==",
        //             "9dfzbIYDt28zTyZfbcll+g=="
        //         )
        //     )
        // )

        metadata.files["ia7OEEEyXMoRa1QWQk8r"] = file1
        metadata.files["n9WXAIXO2wRY4R8nXwmo"] = file2

        return DecryptedFolderMetadataFile(metadata, users, mutableMapOf(), E2EVersion.V2_0.value)
    }
}

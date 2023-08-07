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
package com.owncloud.android.ui.asynctasks

import android.os.AsyncTask
import com.nextcloud.client.account.User
import com.nextcloud.client.network.ClientFactory
import com.nextcloud.common.NextcloudClient
import com.owncloud.android.R
import com.owncloud.android.datamodel.ArbitraryDataProvider
import com.owncloud.android.datamodel.OCFile
import com.owncloud.android.lib.resources.shares.OCShare
import com.owncloud.android.lib.resources.shares.ShareType
import com.owncloud.android.lib.resources.users.GetPublicKeyRemoteOperation
import com.owncloud.android.ui.activity.FileActivity
import com.owncloud.android.ui.helpers.FileOperationsHelper
import com.owncloud.android.utils.DisplayUtils
import com.owncloud.android.utils.EncryptionUtils
import java.lang.ref.WeakReference

class SecureShareTask(
    val currentUser: User,
    val clientFactory: ClientFactory,
    private val shareeName: String,
    val arbitraryDataProvider: ArbitraryDataProvider,
    private val fileOperationsHelper: FileOperationsHelper,
    val file: OCFile,
    private val activityWeakReference: WeakReference<FileActivity>
) : AsyncTask<Void, Void, Int>() {
    override fun onPreExecute() {
        super.onPreExecute()

        activityWeakReference.get()?.let {
            it.showLoadingDialog(it.getString(R.string.wait_a_moment))
        }
    }

    override fun doInBackground(vararg params: Void): Int {
        return share()
    }

    override fun onPostExecute(result: Int) {
        super.onPostExecute(result)

        if (result != 0) {
            activityWeakReference.get()?.let {
                DisplayUtils.showSnackMessage(it, result)
            }
        }
    }

    private fun share(): Int {
        // secure share, first check if user has e2e
        try {
            val nextcloudClient: NextcloudClient = clientFactory.createNextcloudClient(currentUser)
            val result = GetPublicKeyRemoteOperation(shareeName).execute(nextcloudClient)
            if (result.isSuccess) { // TODO check first if we already have it, TOFU!
                // store it
                EncryptionUtils.savePublicKey(
                    currentUser,
                    result.resultData,
                    shareeName,
                    arbitraryDataProvider
                )
            } else {
                return R.string.secure_share_not_set_up
            }

            // no option, thus directly share it
            fileOperationsHelper.shareFileWithSharee(
                file,
                shareeName,
                ShareType.USER,
                OCShare.SHARE_PERMISSION_FLAG,
                false,
                null,
                -1,
                "",
                null,
                false
            )
        } catch (e: Exception) {
            R.string.secure_sharing_failed
        }

        return 0
    }
} 

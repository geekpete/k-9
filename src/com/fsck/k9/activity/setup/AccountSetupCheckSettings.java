
package com.fsck.k9.activity.setup;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Process;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.fsck.k9.*;
import com.fsck.k9.activity.K9Activity;
import com.fsck.k9.controller.MessagingController;
import com.fsck.k9.mail.AuthenticationFailedException;
import com.fsck.k9.mail.CertificateValidationException;
import com.fsck.k9.mail.ClientCertificateAliasRequiredException;
import com.fsck.k9.mail.ClientCertificateRequiredException;
import com.fsck.k9.mail.Store;
import com.fsck.k9.mail.Transport;
import com.fsck.k9.mail.store.WebDavStore;
import com.fsck.k9.mail.filter.Hex;
import com.fsck.k9.net.ssl.SslHelper;
import com.fsck.k9.security.KeyChainKeyManager;

import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.List;

/**
 * Checks the given settings to make sure that they can be used to send and
 * receive mail.
 * 
 * XXX NOTE: The manifest for this app has it ignore config changes, because
 * it doesn't correctly deal with restarting while its thread is running.
 */
public class AccountSetupCheckSettings extends K9Activity implements OnClickListener {

    public static final int ACTIVITY_REQUEST_CODE = 1;

    private static final String EXTRA_ACCOUNT = "account";

    private static final String EXTRA_CHECK_DIRECTION ="checkDirection";

    private static final String EXTRA_PROMT_FOR_CLIENT_CERTIFICATE = "promtForClientCertificate";

    private static final String EXTRA_CLIENT_CERTIFICATE_SET = "clientCertificateSet";

    public enum CheckDirection {
        INCOMING,
        OUTGOING
    }

    private Handler mHandler = new Handler();

    private ProgressBar mProgressBar;

    private TextView mMessageView;

    private Account mAccount;

    private boolean mPromptForClientCertificate;

    private boolean mIsClientCertSet;

    private CheckDirection mDirection;

    private boolean mCanceled;

    private boolean mDestroyed;

    public static void actionCheckSettings(Activity context, Account account,
            CheckDirection direction,
            boolean promptForClientCertificate) {
        actionCheckSettings(context, account, direction, promptForClientCertificate, false);
    }

    private static void actionCheckSettings(Activity context, Account account,
            CheckDirection direction,
            boolean promptForClientCertificate, boolean clientCertificateSet) {
        Intent i = new Intent(context, AccountSetupCheckSettings.class);
        i.putExtra(EXTRA_ACCOUNT, account.getUuid());
        i.putExtra(EXTRA_CHECK_DIRECTION, direction);
        i.putExtra(EXTRA_PROMT_FOR_CLIENT_CERTIFICATE, promptForClientCertificate);
        i.putExtra(EXTRA_CLIENT_CERTIFICATE_SET, clientCertificateSet);
        context.startActivityForResult(i, ACTIVITY_REQUEST_CODE);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.account_setup_check_settings);
        mMessageView = (TextView)findViewById(R.id.message);
        mProgressBar = (ProgressBar)findViewById(R.id.progress);
        ((Button)findViewById(R.id.cancel)).setOnClickListener(this);

        setMessage(R.string.account_setup_check_settings_retr_info_msg);
        mProgressBar.setIndeterminate(true);

        String accountUuid = getIntent().getStringExtra(EXTRA_ACCOUNT);
        mAccount = Preferences.getPreferences(this).getAccount(accountUuid);
        mDirection = (CheckDirection) getIntent().getSerializableExtra(EXTRA_CHECK_DIRECTION);

        mPromptForClientCertificate = getIntent().getBooleanExtra(EXTRA_PROMT_FOR_CLIENT_CERTIFICATE, false);
        mIsClientCertSet = getIntent().getBooleanExtra(EXTRA_CLIENT_CERTIFICATE_SET, false);

        new Thread() {
            @Override
            public void run() {
                Store store = null;
                Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
                try {
                    if (mPromptForClientCertificate) {
                        if (K9.DEBUG)
                            Log.d(K9.LOG_TAG,
                                    "AccountSetupCheckSettings will prompt for client certificate");
                        SslHelper.setInteractiveClientCertificateAliasSelectionRequired(true);
                    } else {
                        if (K9.DEBUG)
                            Log.d(K9.LOG_TAG,
                                    "AccountSetupCheckSettings will NOT prompt for client certificate");
                    }

                    if (mDestroyed) {
                        return;
                    }
                    if (mCanceled) {
                        finish();
                        return;
                    }

                    final MessagingController ctrl = MessagingController.getInstance(getApplication());
                    ctrl.clearCertificateErrorNotifications(AccountSetupCheckSettings.this,
                            mAccount, mDirection);

                    if (mDirection.equals(CheckDirection.INCOMING)) {
                        // refresh URI that stores settings in order to include
                        // client certificate set by user
                        store = mAccount.getRemoteStore(mIsClientCertSet);

                        if (store instanceof WebDavStore) {
                            setMessage(R.string.account_setup_check_settings_authenticate);
                        } else {
                            setMessage(R.string.account_setup_check_settings_check_incoming_msg);
                        }
                        store.checkSettings();

                        if (store instanceof WebDavStore) {
                            setMessage(R.string.account_setup_check_settings_fetch);
                        }
                        MessagingController.getInstance(getApplication()).listFoldersSynchronous(mAccount, true, null);
                        MessagingController.getInstance(getApplication()).synchronizeMailbox(mAccount, mAccount.getInboxFolderName(), null, null);
                    }
                    if (mDestroyed) {
                        return;
                    }
                    if (mCanceled) {
                        finish();
                        return;
                    }
                    if (mDirection.equals(CheckDirection.OUTGOING)) {
                        if (!(mAccount.getRemoteStore() instanceof WebDavStore)) {
                            setMessage(R.string.account_setup_check_settings_check_outgoing_msg);
                        }
                        Transport transport = Transport.getInstance(mAccount);
                        transport.close();
                        transport.open();
                        transport.close();
                    }
                    if (mDestroyed) {
                        return;
                    }
                    if (mCanceled) {
                        finish();
                        return;
                    }
                    setResult(RESULT_OK);
                    finish();
                } catch (final AuthenticationFailedException afe) {
                    Log.e(K9.LOG_TAG, "Error while testing settings", afe);
                    showErrorDialog(
                        R.string.account_setup_failed_dlg_auth_message_fmt,
                        afe.getMessage() == null ? "" : afe.getMessage());
                } catch (final CertificateValidationException cve) {
                    handleCertificateValidationException(cve);
                } catch (final ClientCertificateRequiredException e) {
                    handleClientCertificateRequiredException(e);
                } catch (final ClientCertificateAliasRequiredException ccr) {
                    handleClientCertificateAliasRequiredException(ccr);
                } catch (final Throwable t) {
                    Log.e(K9.LOG_TAG, "Error while testing settings", t);
                    showErrorDialog(
                        R.string.account_setup_failed_dlg_server_message_fmt,
                        (t.getMessage() == null ? "" : t.getMessage()));
                } finally {
                    SslHelper.setInteractiveClientCertificateAliasSelectionRequired(false);
                }
            }

        }
                .start();
    }

    private void handleCertificateValidationException(CertificateValidationException cve) {
        Log.e(K9.LOG_TAG, "Error while testing settings", cve);

        X509Certificate[] chain = cve.getCertChain();
        // Avoid NullPointerException in acceptKeyDialog()
        if (chain != null) {
            if (mPromptForClientCertificate) {
                // TODO
                // accept server certificate if we are authorizing using
                // client-side certificate
                acceptCertificate(chain[0]);
            } else {
                acceptKeyDialog(
                        R.string.account_setup_failed_dlg_certificate_message_fmt,
                        cve);
            }
        } else {
            showErrorDialog(
                    R.string.account_setup_failed_dlg_server_message_fmt,
                    (cve.getMessage() == null ? "" : cve.getMessage()));
        }
    }

    /**
     * TODO
     */
    private void handleClientCertificateRequiredException(ClientCertificateRequiredException e) {
        if (SslHelper.isClientCertificateSupportAvailable()) {
            if (mPromptForClientCertificate) {
                // there are no certs if we are back here - suggest installing
                // new certs
                runOnUiThread(new Runnable() {
                    public void run() {

                        AlertDialog.Builder builder = new AlertDialog.Builder(
                                AccountSetupCheckSettings.this);
                        builder.setMessage(R.string.no_ccerts)
                                .setPositiveButton(android.R.string.ok,
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int id) {

                                                // redirect user to security
                                                // settings
                                                startActivity(new Intent(
                                                        android.provider.Settings.ACTION_SECURITY_SETTINGS));

                                                finish();
                                                return;

                                            }
                                        })
                                .setNegativeButton(android.R.string.cancel,
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int id) {
                                                // TODO
                                                // handleCertificateValidationException(e);
                                            }
                                        });
                        builder.create();
                        builder.show();
                    }
                });

            } else {

                // ask if user want to pick a client certificate - if not then
                // just go with CertificateValidationException block as always
                // before
                runOnUiThread(new Runnable() {
                    public void run() {
                        int msgId = R.string.do_you_want_to_pick_ccert;
                        if (mIsClientCertSet) {
                            // client already set certificate and we still can't
                            // log in
                            msgId = R.string.do_you_want_to_pick_ccert_error;
                        }

                        AlertDialog.Builder builder = new AlertDialog.Builder(
                                AccountSetupCheckSettings.this);
                        builder.setMessage(msgId)
                                .setPositiveButton(android.R.string.ok,
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int id) {

                                                // accept server certificate if
                                                // we are authorizing using
                                                // client-side certificate
                                                AccountSetupCheckSettings.actionCheckSettings(
                                                        AccountSetupCheckSettings.this, mAccount,
                                                        mDirection, true);

                                            }
                                        })
                                .setNegativeButton(android.R.string.cancel,
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int id) {
                                                // TODO
                                                // handleCertificateValidationException(e);
                                            }
                                        });
                        builder.create();
                        builder.show();
                    }
                });

            }

        } else {
            // Certificates center (KeyChain) is not available in this Android
            // version - inform user about this and go with
            // CertificateValidationException block as always before

            runOnUiThread(new Runnable() {
                public void run() {
                    AlertDialog.Builder builder = new AlertDialog.Builder(
                            AccountSetupCheckSettings.this);
                    builder.setMessage(R.string.ccert_not_available)
                            .setNeutralButton(android.R.string.ok,
                                    new DialogInterface.OnClickListener() {
                                        public void onClick(DialogInterface dialog, int id) {
                                            // TODO
                                            // handleCertificateValidationException(e);
                                        }
                                    });
                    builder.create();
                    builder.show();
                }
            });
        }
    }

    /**
     * TODO
     * 
     * @param e
     */
    private void handleClientCertificateAliasRequiredException(
            ClientCertificateAliasRequiredException ccr) {
        if (K9.DEBUG)
            Log.d(K9.LOG_TAG, "Client certificate required: " + ccr.getMessage());

        String alias = mAccount.getClientCertificateAlias();

        alias = KeyChainKeyManager.interactivelyChooseClientCertificateAlias(
                AccountSetupCheckSettings.this,
                ccr.getKeyTypes(),
                ccr.getIssuers(),
                ccr.getHostName(),
                ccr.getPort(),
                alias);

        // save client certificate
        if (alias != null) {
            if (mDirection.equals(CheckDirection.INCOMING)) {
                if (K9.DEBUG)
                    Log.d(K9.LOG_TAG, "Setting store client certificate alias to: " + alias);
                mAccount.setClientCertificateAlias(alias);
            } else if (mDirection.equals(CheckDirection.OUTGOING)) {
                if (K9.DEBUG)
                    Log.d(K9.LOG_TAG, "Setting transport client certificate alias to: " + alias);
                mAccount.setClientCertificateAlias(alias);
            }

            // don't ask for client certificate anymore
            AccountSetupCheckSettings.actionCheckSettings(AccountSetupCheckSettings.this, mAccount,
                    mDirection, false, true);
        } else {
            showErrorDialog(R.string.account_setup_failed_dlg_ccert_required);
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        mDestroyed = true;
        mCanceled = true;
    }

    private void setMessage(final int resId) {
        mHandler.post(new Runnable() {
            public void run() {
                if (mDestroyed) {
                    return;
                }
                mMessageView.setText(getString(resId));
            }
        });
    }

    private void showErrorDialog(final int msgResId, final Object... args) {
        mHandler.post(new Runnable() {
            public void run() {
                if (mDestroyed) {
                    return;
                }
                mProgressBar.setIndeterminate(false);
                new AlertDialog.Builder(AccountSetupCheckSettings.this)
                .setTitle(getString(R.string.account_setup_failed_dlg_title))
                .setMessage(getString(msgResId, args))
                .setCancelable(true)
                .setNegativeButton(
                    getString(R.string.account_setup_failed_dlg_continue_action),

                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        mCanceled = false;
                        setResult(RESULT_OK);
                        finish();
                    }
                })
                .setPositiveButton(
                    getString(R.string.account_setup_failed_dlg_edit_details_action),
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        finish();
                    }
                })
                .show();
            }
        });
    }

    private void acceptKeyDialog(final int msgResId,
            final CertificateValidationException ex) {
        mHandler.post(new Runnable() {
            public void run() {
                if (mDestroyed) {
                    return;
                }
                String exMessage = "Unknown Error";

                if (ex != null) {
                    if (ex.getCause() != null) {
                        if (ex.getCause().getCause() != null) {
                            exMessage = ex.getCause().getCause().getMessage();

                        } else {
                            exMessage = ex.getCause().getMessage();
                        }
                    } else {
                        exMessage = ex.getMessage();
                    }
                }

                mProgressBar.setIndeterminate(false);
                StringBuilder chainInfo = new StringBuilder(100);
                MessageDigest sha1 = null;
                try {
                    sha1 = MessageDigest.getInstance("SHA-1");
                } catch (NoSuchAlgorithmException e) {
                    Log.e(K9.LOG_TAG, "Error while initializing MessageDigest", e);
                }

                final X509Certificate[] chain = ex.getCertChain();
                // We already know chain != null (tested before calling this method)
                for (int i = 0; i < chain.length; i++) {
                    // display certificate chain information
                    //TODO: localize this strings
                    chainInfo.append("Certificate chain[").append(i).append("]:\n");
                    chainInfo.append("Subject: ").append(chain[i].getSubjectDN().toString()).append("\n");

                    // display SubjectAltNames too
                    // (the user may be mislead into mistrusting a certificate
                    //  by a subjectDN not matching the server even though a
                    //  SubjectAltName matches)
                    try {
                        final Collection < List<? >> subjectAlternativeNames = chain[i].getSubjectAlternativeNames();
                        if (subjectAlternativeNames != null) {
                            // The list of SubjectAltNames may be very long
                            //TODO: localize this string
                            StringBuilder altNamesText = new StringBuilder();
                            altNamesText.append("Subject has ").append(subjectAlternativeNames.size()).append(" alternative names\n");

                            // we need these for matching
                            String storeURIHost = (Uri.parse(mAccount.getStoreUri())).getHost();
                            String transportURIHost = (Uri.parse(mAccount.getTransportUri())).getHost();

                            for (List<?> subjectAlternativeName : subjectAlternativeNames) {
                                Integer type = (Integer)subjectAlternativeName.get(0);
                                Object value = subjectAlternativeName.get(1);
                                String name = "";
                                switch (type.intValue()) {
                                case 0:
                                    Log.w(K9.LOG_TAG, "SubjectAltName of type OtherName not supported.");
                                    continue;
                                case 1: // RFC822Name
                                    name = (String)value;
                                    break;
                                case 2:  // DNSName
                                    name = (String)value;
                                    break;
                                case 3:
                                    Log.w(K9.LOG_TAG, "unsupported SubjectAltName of type x400Address");
                                    continue;
                                case 4:
                                    Log.w(K9.LOG_TAG, "unsupported SubjectAltName of type directoryName");
                                    continue;
                                case 5:
                                    Log.w(K9.LOG_TAG, "unsupported SubjectAltName of type ediPartyName");
                                    continue;
                                case 6:  // Uri
                                    name = (String)value;
                                    break;
                                case 7: // ip-address
                                    name = (String)value;
                                    break;
                                default:
                                    Log.w(K9.LOG_TAG, "unsupported SubjectAltName of unknown type");
                                    continue;
                                }

                                // if some of the SubjectAltNames match the store or transport -host,
                                // display them
                                if (name.equalsIgnoreCase(storeURIHost) || name.equalsIgnoreCase(transportURIHost)) {
                                    //TODO: localize this string
                                    altNamesText.append("Subject(alt): ").append(name).append(",...\n");
                                } else if (name.startsWith("*.") && (
                                            storeURIHost.endsWith(name.substring(2)) ||
                                            transportURIHost.endsWith(name.substring(2)))) {
                                    //TODO: localize this string
                                    altNamesText.append("Subject(alt): ").append(name).append(",...\n");
                                }
                            }
                            chainInfo.append(altNamesText);
                        }
                    } catch (Exception e1) {
                        // don't fail just because of subjectAltNames
                        Log.w(K9.LOG_TAG, "cannot display SubjectAltNames in dialog", e1);
                    }

                    chainInfo.append("Issuer: ").append(chain[i].getIssuerDN().toString()).append("\n");
                    if (sha1 != null) {
                        sha1.reset();
                        try {
                            char[] sha1sum = Hex.encodeHex(sha1.digest(chain[i].getEncoded()));
                            chainInfo.append("Fingerprint (SHA-1): ").append(new String(sha1sum)).append("\n");
                        } catch (CertificateEncodingException e) {
                            Log.e(K9.LOG_TAG, "Error while encoding certificate", e);
                        }
                    }
                }

                new AlertDialog.Builder(AccountSetupCheckSettings.this)
                .setTitle(getString(R.string.account_setup_failed_dlg_invalid_certificate_title))
                //.setMessage(getString(R.string.account_setup_failed_dlg_invalid_certificate)
                .setMessage(getString(msgResId, exMessage)
                            + " " + chainInfo.toString()
                           )
                .setCancelable(true)
                .setPositiveButton(
                    getString(R.string.account_setup_failed_dlg_invalid_certificate_accept),
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        acceptCertificate(chain[0]);
                    }
                })
                .setNegativeButton(
                    getString(R.string.account_setup_failed_dlg_invalid_certificate_reject),
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        finish();
                    }
                })
                .show();
            }
        });
    }

    private void acceptCertificate(X509Certificate certificate) {
        try {
            mAccount.addCertificate(mDirection, certificate);
        } catch (CertificateException e) {
            showErrorDialog(
                    R.string.account_setup_failed_dlg_certificate_message_fmt,
                    e.getMessage() == null ? "" : e.getMessage());
        }
        AccountSetupCheckSettings.actionCheckSettings(AccountSetupCheckSettings.this, mAccount,
                mDirection, mPromptForClientCertificate);
    }

    @Override
    public void onActivityResult(int reqCode, int resCode, Intent data) {
        setResult(resCode);
        finish();
    }

    private void onCancel() {
        mCanceled = true;
        setMessage(R.string.account_setup_check_settings_canceling_msg);
    }

    public void onClick(View v) {
        switch (v.getId()) {
        case R.id.cancel:
            onCancel();
            break;
        }
    }
}

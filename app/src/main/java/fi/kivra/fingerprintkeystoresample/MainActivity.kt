package fi.kivra.fingerprintkeystoresample

import android.annotation.TargetApi
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.google.android.material.snackbar.Snackbar

import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.content_main.*
import timber.log.Timber
import java.io.IOException
import java.lang.Exception
import java.security.*
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.cert.CertificateException

class MainActivity : AppCompatActivity() {
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var biometricPrompt: BiometricPrompt

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private var defaultCipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")
    private var cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")

    private var encryptedPassword = ""

    private lateinit var sampleText : TextView
    private val activity = this

    companion object {
        private const val IV_SEPARATOR = "]"
        private const val DEFAULT_KEY_NAME = "defaultKey"
        private const val SUPER_SECRET_KEY = "SecretKey"
        private const val SUPER_SECRET_PASSWORD = "SecretPassword123"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Login to encrypt/decrypt data,")
            .setNegativeButtonText("dialog_btn__cancel")
            .build()

        biometricPrompt = BiometricPrompt(this as FragmentActivity, MainExecutor(), encryptionAuthenticationCallback())

        sampleText = findViewById(R.id.sampleText)
        val encryptBtn = findViewById<View>(R.id.encryptBtn)
        val decryptBtn = findViewById<View>(R.id.decryptBtn)

        generateKey(DEFAULT_KEY_NAME,true)
        generateKey(SUPER_SECRET_KEY,false)

        encryptBtn.setOnClickListener {
            try {
                initCipher(cipher, SUPER_SECRET_KEY, Cipher.ENCRYPT_MODE,null)
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            } catch (ex: Exception) {
                initCipher(defaultCipher, DEFAULT_KEY_NAME, Cipher.ENCRYPT_MODE,null)
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(defaultCipher))
            }

        }

        decryptBtn.setOnClickListener {
            try {
                initCipher(cipher, SUPER_SECRET_KEY, Cipher.DECRYPT_MODE,fetchIVParams(encryptedPassword))
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            } catch (ex: Exception) {
                initCipher(defaultCipher, DEFAULT_KEY_NAME, Cipher.DECRYPT_MODE,fetchIVParams(encryptedPassword))
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(defaultCipher))
            }

        }

        decryptBtn.isEnabled = false
    }

    private fun encryptionAuthenticationCallback(): BiometricPrompt.AuthenticationCallback {
        return object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)

                assert(result.cryptoObject != null)

                try {
                    if (encryptedPassword.isBlank()) {
                        encryptedPassword = encrypt(SUPER_SECRET_PASSWORD,result.cryptoObject)
                        sampleText.text = encryptedPassword
                        encryptBtn.isEnabled = false
                        decryptBtn.isEnabled = true
                    } else {
                        val decryptedPassword =
                            decrypt(encryptedPassword,result.cryptoObject)
                        sampleText.text = decryptedPassword
                        encryptedPassword = ""
                        encryptBtn.isEnabled = true
                        decryptBtn.isEnabled = false
                    }
                } catch (ex: Exception) {
                    Toast.makeText(activity,"${ex.message}",Toast.LENGTH_LONG).show()
                    Timber.e(ex)
                }
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
            }
        }
    }

    class MainExecutor : Executor {
        private val mainThreadHandler = Handler(Looper.getMainLooper())

        override fun execute(command: Runnable) {
            mainThreadHandler.post(command)
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun generateIVParams(cipher: Cipher): String {
        val iv = cipher.iv
        val ivString = Base64.encodeToString(iv, Base64.DEFAULT)
        return ivString + IV_SEPARATOR
    }


    private fun fetchIVParams(data: String): IvParameterSpec {
        val split = data.split(IV_SEPARATOR.toRegex())
        if (split.size != 2) throw IllegalArgumentException("Passed data is incorrect. There was no IV specified with it.")

        return IvParameterSpec(Base64.decode(split[0], Base64.DEFAULT))
    }


    /**
     * Encrypt the given data with the given key and return the encrypted result
     */
    fun encrypt(
        data: String,
        cryptoObject: BiometricPrompt.CryptoObject?
    ): String {
        var rightCipher = this.cipher

        if(cryptoObject != null) {
            rightCipher = cryptoObject.cipher
        }
        val ivParams = generateIVParams(rightCipher)
        val bytes = rightCipher.doFinal(data.toByteArray())
        val encryptedKey = Base64.encodeToString(bytes, Base64.DEFAULT)

        Timber.i("ivString: ${ivParams} / encodedString: ${encryptedKey}")

        return ivParams + encryptedKey
    }

    /**
     * Decrypt the given data with the given key and return the decrypted result
     */
    fun decrypt(data: String,cryptoObject: BiometricPrompt.CryptoObject?): String {
        val split = data.split(IV_SEPARATOR.toRegex())
        if (split.size != 2) throw IllegalArgumentException("Passed data is incorrect. There was no IV specified with it.")

        val ivString = split[0]
        val encodedString = split[1]
        val ivSpec = IvParameterSpec(Base64.decode(ivString, Base64.DEFAULT))

        var rightCipher = this.cipher

        if(cryptoObject != null) {
            rightCipher = cryptoObject.cipher
        }

        val encryptedData = Base64.decode(encodedString, Base64.DEFAULT)
        val result = rightCipher.doFinal(encryptedData)
        return if (result != null) { String(result) } else { "" }
    }


    /**
     * Generates a Public/Private Key pair with the alias passed as a parameter
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun generateKey(keyName: String,invalidatedByBiometricEnrollment: Boolean): Boolean {
        if (!keyStore.containsAlias(keyName)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)


            keyGenerator.init(builder.build())

            keyGenerator.generateKey()
            return true
        }

        return false
    }

    /**
     * Initialize the [Cipher] instance with the created key in the [createKey] method.
     *
     * @param keyName the key name to init the cipher
     * @return `true` if initialization succeeded, `false` if the lock screen has been disabled or
     * reset after key generation, or if a fingerprint was enrolled after key generation.
     */
    private fun initCipher(cipher: Cipher, keyName: String, mode: Int, params: IvParameterSpec?): Boolean {
        try {
            keyStore.load(null)

            if(params == null) {
                cipher.init(mode, keyStore.getKey(keyName, null) as SecretKey)
            } else {
                cipher.init(mode, keyStore.getKey(keyName, null) as SecretKey,params)
            }
            return true
        } catch (e: Exception) {
            when (e) {
                is KeyPermanentlyInvalidatedException -> return false
                is KeyStoreException,
                is CertificateException,
                is UnrecoverableKeyException,
                is IOException,
                is NoSuchAlgorithmException,
                is InvalidKeyException -> throw RuntimeException("Failed to init Cipher", e)
                else -> throw e
            }
        }
    }
}

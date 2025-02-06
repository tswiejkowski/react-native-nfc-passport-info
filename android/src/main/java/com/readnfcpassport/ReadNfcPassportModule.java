package com.readnfcpassport;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;

import net.sf.scuba.smartcards.CardService;

import org.jmrtd.BACKey;
import org.jmrtd.BACKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.lds.CardAccessFile;
import org.jmrtd.lds.PACEInfo;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.SecurityInfo;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.jmrtd.Util;
import net.sf.scuba.tlv.TLVInputStream;
import net.sf.scuba.tlv.TLVUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.Security;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

@ReactModule(name = ReadNfcPassportModule.NAME)
public class ReadNfcPassportModule extends ReactContextBaseJavaModule implements LifecycleEventListener, ActivityEventListener {
  public static final String NAME = "ReadNfcPassport";
  private static final String E_NOT_SUPPORTED = "E_NOT_SUPPORTED";
  private static final String E_NOT_ENABLED = "E_NOT_ENABLED";
  private static final String E_SCAN_CANCELED = "E_SCAN_CANCELED";
  private static final String E_SCAN_FAILED = "E_SCAN_FAILED";
  private static final String E_SCAN_FAILED_DISCONNECT = "E_SCAN_FAILED_DISCONNECT";
  private static final String E_ONE_REQ_AT_A_TIME = "E_ONE_REQ_AT_A_TIME";
  private static final String KEY_IS_SUPPORTED = "isSupported";
  private static final String KEY_FIRST_NAME = "firstName";
  private static final String KEY_LAST_NAME = "lastName";
  private static final String KEY_GENDER = "gender";
  private static final String KEY_ISSUER = "issuingAuthority";
  private static final String KEY_NATIONALITY = "nationality";
  private static final String KEY_PHOTO = "photo";
  private static final String PARAM_DOC_NUM = "documentNumber";
  private static final String PARAM_DOB = "dateOfBirth";
  private static final String PERSONAL_NUM = "personalNumber";
  private static final String MRZ = "passportMRZ";
  private static final String PARAM_DOE = "dateOfExpiry";
  private static final String TAG = "passportreader";
  private static final String JPEG_DATA_URI_PREFIX = "data:image/jpeg;base64,";
  private static final String DSC = "documentSigningCertificate";
  private static final String DSCV = "documentSigningCertificateVerified";
  private static final String PDNT = "passportDataNotTampered";
  
  private static final Provider BC_PROVIDER = Util.getBouncyCastleProvider();

  private final ReactApplicationContext reactContext;
  private Promise scanPromise;
  private ReadableMap opts;

  public ReadNfcPassportModule(ReactApplicationContext reactContext) {
    super(reactContext);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);

    reactContext.addLifecycleEventListener(this);
    reactContext.addActivityEventListener(this);

    this.reactContext = reactContext;
  }

    @Override
    public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
    }

    @Override
    public void onNewIntent(Intent intent) {
        Log.d("LONG CHECK", "onNewIntent ");
        try {
            if (scanPromise == null) return;
            if (!NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) return;

            Tag tag = intent.getExtras().getParcelable(NfcAdapter.EXTRA_TAG);
            if (!Arrays.asList(tag.getTechList()).contains(IsoDep.class.getName())) return;
            Log.d("LONG CHECK", "onNewIntent "+ opts.getString(PARAM_DOC_NUM) + opts.getString(PARAM_DOB) + opts.getString(PARAM_DOE));
            BACKeySpec bacKey = new BACKey(
                    opts.getString(PARAM_DOC_NUM),
                    opts.getString(PARAM_DOB),
                    opts.getString(PARAM_DOE)
            );
          new com.readnfcpassport.ReadNfcPassportModule.ReadTask(IsoDep.get(tag), bacKey).execute();
        } catch (Exception e){}
    }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }


  @Override
  public Map<String, Object> getConstants() {
      final Map<String, Object> constants = new HashMap<>();
      boolean hasNFC = reactContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC);
      constants.put(KEY_IS_SUPPORTED, hasNFC);
      return constants;
  }

  @ReactMethod
  public void cancel(final Promise promise) {
      Log.d("LONG CHECK", "cancel ");
      try {
          if (scanPromise != null) {
              scanPromise.reject(E_SCAN_CANCELED, "canceled");
          }

          resetState();
          promise.resolve(null);
      }catch (Exception e) {}
  }

  @ReactMethod
  public void scan(final ReadableMap opts, final Promise promise) {
      Log.d("LONG CHECK", "scan ");
      try {
          NfcAdapter mNfcAdapter = NfcAdapter.getDefaultAdapter(this.reactContext);
          if (mNfcAdapter == null) {
              promise.reject(E_NOT_SUPPORTED, "NFC chip reading not supported");
              return;
          }

          if (!mNfcAdapter.isEnabled()) {
              promise.reject(E_NOT_ENABLED, "NFC chip reading not enabled");
              return;
          }

          if (scanPromise != null) {
              promise.reject(E_ONE_REQ_AT_A_TIME, "Already running a scan");
              return;
          }

          this.opts = opts;
          this.scanPromise = promise;
      } catch (Exception e) {

      }
  }

  private void resetState() {
      scanPromise = null;
      opts = null;
  }

  @Override
  public void onHostDestroy() {
      resetState();
  }

  @Override
  public void onHostResume() {
      Log.d("LONG CHECK", "onHostResume ");
      try {
          NfcAdapter mNfcAdapter = NfcAdapter.getDefaultAdapter(reactContext);
          if (mNfcAdapter == null) return;

          Activity activity = getCurrentActivity();
          Intent intent = new Intent(activity.getApplicationContext(), activity.getClass());
          intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
          int pendingFlags;
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
              pendingFlags = PendingIntent.FLAG_MUTABLE;
          } else {
              pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT;
          }
          PendingIntent pendingIntent = PendingIntent.getActivity(getCurrentActivity(), 0, intent, pendingFlags);//PendingIntent.FLAG_UPDATE_CURRENT);
          String[][] filter = new String[][]{new String[]{IsoDep.class.getName()}};
          mNfcAdapter.enableForegroundDispatch(getCurrentActivity(), pendingIntent, null, filter);
      }catch (Exception e) {}
  }

  @Override
  public void onHostPause() {
      Log.d("LONG CHECK", "onHostPause ");
      try {
          NfcAdapter mNfcAdapter = NfcAdapter.getDefaultAdapter(reactContext);
          if (mNfcAdapter == null) return;
          mNfcAdapter.disableForegroundDispatch(getCurrentActivity());
      }catch (Exception e){}
  }

  private static String exceptionStack(Throwable exception) {
      Log.d("LONG CHECK", "exceptionStack ");
      try {
          StringBuilder s = new StringBuilder();
          String exceptionMsg = exception.getMessage();
          if (exceptionMsg != null) {
              s.append(exceptionMsg);
              s.append(" - ");
          }
          s.append(exception.getClass().getSimpleName());
          StackTraceElement[] stack = exception.getStackTrace();

          if (stack.length > 0) {
              int count = 3;
              boolean first = true;
              boolean skip = false;
              String file = "";
              s.append(" (");
              for (StackTraceElement element : stack) {
                  if (count > 0 && element.getClassName().startsWith("io.tradle")) {
                      if (!first) {
                          s.append(" < ");
                      } else {
                          first = false;
                      }

                      if (skip) {
                          s.append("... < ");
                          skip = false;
                      }

                      if (file.equals(element.getFileName())) {
                          s.append("*");
                      } else {
                          file = element.getFileName();
                          s.append(file.substring(0, file.length() - 5)); // remove ".java"
                          count -= 1;
                      }
                      s.append(":").append(element.getLineNumber());
                  } else {
                      skip = true;
                  }
              }
              if (skip) {
                  if (!first) {
                      s.append(" < ");
                  }
                  s.append("...");
              }
              s.append(")");
          }
          return s.toString();
      }catch (Exception e) {
          return null;
      }
  }

  private static String toBase64(final Bitmap bitmap, final int quality) {
      try {
          ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
          bitmap.compress(Bitmap.CompressFormat.JPEG, quality, byteArrayOutputStream);
          byte[] byteArray = byteArrayOutputStream.toByteArray();
          return JPEG_DATA_URI_PREFIX + Base64.encodeToString(byteArray, Base64.NO_WRAP);
      }catch (Exception e) {
          return null;
      }
  }

  private static String convertByteToHexadecimal(byte[] byteArray)
  {
      String hex = "";

      // Iterating through each byte in the array
      for (byte i : byteArray) {
          hex += String.format("%02X", i);
      }

      return hex;
  }

  /**
     * This object, including tag and length, as byte array.
     * 
     * @return this object, including tag and length, as byte array
     */
    public byte[] getEncoded(int tagInt, int lenghtInt, byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(TLVUtil.getTagAsBytes(tagInt));
            out.write(TLVUtil.getLengthAsBytes(lenghtInt));
            out.write(data);
        } catch (Exception e) {
            Log.w(TAG, e);
        }
        return out.toByteArray();
    }

  /**
	 * Verifies the signature over the contents of the security object.
	 * Clients can also use the accessors of this class and check the
	 * validity of the signature for themselves.
	 * 
	 * See RFC 3369, Cryptographic Message Syntax, August 2002,
	 * Section 5.4 for details.
	 * 
	 * @param docSigningCert the certificate to use
	 *        (should be X509 certificate)
	 * 
	 * @return status of the verification
	 * 
	 * @throws GeneralSecurityException if something goes wrong
	 */
	private static boolean checkDocSignature(Certificate docSigningCert, SODFile sodFile) throws GeneralSecurityException {
		byte[] eContent = sodFile.getEContent();
		byte[] signature = sodFile.getEncryptedDigest();

		String digestEncryptionAlgorithm = null;
		try {
			digestEncryptionAlgorithm = sodFile.getDigestEncryptionAlgorithm();
		} catch (Exception e) {
			digestEncryptionAlgorithm = null;
		}
        Log.d("ReadNFC - checkDocSignature", "digestEncryptionAlgorithm: " + digestEncryptionAlgorithm);

		/*
		 * For the cases where the signature is simply a digest (haven't seen a passport like this, 
		 * thus this is guessing)
		 */
		if (digestEncryptionAlgorithm == null) {
			String digestAlg = sodFile.getSignerInfoDigestAlgorithm();
			MessageDigest digest = null;
			try {
				digest = MessageDigest.getInstance(digestAlg);
			} catch (Exception e) {
				digest = MessageDigest.getInstance(digestAlg, BC_PROVIDER);
			}
			digest.update(eContent);
			byte[] digestBytes = digest.digest();
            Log.d("ReadNFC - checkDocSignature", "digestEncryptionAlgorithm is null, digestBytes: " + convertByteToHexadecimal(digestBytes) + " - signature: " + convertByteToHexadecimal(signature));

			return Arrays.equals(digestBytes, signature);
		}


		/* For RSA_SA_PSS
		 *    1. the default hash is SHA1,
		 *    2. The hash id is not encoded in OID
		 * So it has to be specified "manually".
		 */
		if ("SSAwithRSA/PSS".equals(digestEncryptionAlgorithm)) {
			String digestAlg = sodFile.getSignerInfoDigestAlgorithm();
			digestEncryptionAlgorithm = digestAlg.replace("-", "") + "withRSA/PSS";
		}

		if ("RSA".equals(digestEncryptionAlgorithm)) {
			String digestJavaString = sodFile.getSignerInfoDigestAlgorithm();
			digestEncryptionAlgorithm = digestJavaString.replace("-", "") + "withRSA";
		}

		Signature sig = null;
		try {
			sig = Signature.getInstance(digestEncryptionAlgorithm);
		} catch (Exception e) {
			sig = Signature.getInstance(digestEncryptionAlgorithm, BC_PROVIDER);
		}
		sig.initVerify(docSigningCert);
		sig.update(eContent);

		return sig.verify(signature);
	}


  private class ReadTask extends AsyncTask<Void, Void, Exception> {

      private IsoDep isoDep;
      private BACKeySpec bacKey;

      public ReadTask(IsoDep isoDep, BACKeySpec bacKey) {
          this.isoDep = isoDep;
          this.bacKey = bacKey;
      }

      private DG1File dg1File;
      private DG2File dg2File;
      private SODFile sodFile;
      private Bitmap bitmap;
      private String documentSigningCertificate;
      private boolean documentSigningCertificateVerified;
      private boolean passportDataNotTampered;

      @Override
      protected Exception doInBackground(Void... params) {
          Log.d("LONG CHECK", "doInBackground ");
          try {
              CardService cardService = CardService.getInstance(isoDep);
              cardService.open();
              PassportService service = new PassportService(cardService, PassportService.EXTENDED_MAX_TRANCEIVE_LENGTH, PassportService.DEFAULT_MAX_BLOCKSIZE, false, false);
              service.open();
              boolean paceSucceeded = false;
              Log.d("LONG CHECK", "bacKey "+ bacKey);
              try {
                  CardAccessFile cardAccessFile = new CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS));
                  Collection<SecurityInfo> securityInfoCollection = cardAccessFile.getSecurityInfos();
                  for (SecurityInfo securityInfo : securityInfoCollection) {
                      if (securityInfo instanceof PACEInfo) {
                          service.doPACE(
                                  bacKey,
                                  securityInfo.getObjectIdentifier(),
                                  PACEInfo.toParameterSpec(((PACEInfo) securityInfo).getParameterId()),
                                  null
                          );
                          paceSucceeded = true;
                      }
                  }
              } catch (Exception e) {
                  Log.w(TAG, e);
              }
              service.sendSelectApplet(paceSucceeded);
              Log.d("LONG CHECK", "paceSucceeded "+ paceSucceeded);
              if (!paceSucceeded) {
                  try {
                      service.getInputStream(PassportService.EF_COM).read();
                  } catch (Exception e) {
                      service.sendSelectApplet(false);
                      service.doBAC(bacKey);
                  }
              }

              InputStream dg1In = service.getInputStream(PassportService.EF_DG1);
              dg1File = new DG1File(dg1In);

              InputStream dg2In = service.getInputStream(PassportService.EF_DG2);
              dg2File = new DG2File(dg2In);

              InputStream sodIn = service.getInputStream(PassportService.EF_SOD);
              sodFile = new SODFile(sodIn);

                X509Certificate docSigningCertificate = sodFile.getDocSigningCertificate();

                StringWriter sw = new StringWriter();
                try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
                    jpw.writeObject(docSigningCertificate);
                } catch (Exception e) {
                      Log.e(TAG,"JcaPEMWriter",e);
                }
                documentSigningCertificate = sw.toString();
                Certificate dsCertificate = (Certificate) docSigningCertificate;
               
                // Init values
                passportDataNotTampered = false;
                documentSigningCertificateVerified = false;

                // Verifies the signature over the contents of the security object
                documentSigningCertificateVerified = checkDocSignature(dsCertificate, sodFile);
                
                // Gets the stored data group hashes.
                Map<Integer, byte[]> storedHashes = sodFile.getDataGroupHashes();
                // Gets the name of the algorithm used in the data group hashes.
                String sodHashAlgorythm = sodFile.getDigestAlgorithm();
                Log.d("ReadNFC - HASHES CHECK", "sodHashAlgorythm: " + sodHashAlgorythm);

                MessageDigest digest = MessageDigest.getInstance(sodHashAlgorythm);

                /* for (int i: storedHashes.keySet()) {
                    Log.d("ReadNFC - HASHES CHECK", " Stored hash of ");
                    Log.d("ReadNFC - HASHES CHECK", " DG" + i + ": ");
                    Log.d("ReadNFC - HASHES CHECK", " Hash value: " + convertByteToHexadecimal(storedHashes.get(i)));
                } */

                InputStream dg1IS = service.getInputStream(PassportService.EF_DG1);
                TLVInputStream tlvIn = new TLVInputStream(dg1IS);
                int tag = tlvIn.readTag();
		        int length = tlvIn.readLength();
                byte[] content = tlvIn.readValue();
                byte[] eContent = getEncoded(tag, length, content);
				byte[] computedHash = digest.digest(eContent);
                
                // Log.d("ReadNFC - HASHES CHECK", " eContent " + convertByteToHexadecimal(eContent));
                Log.d("ReadNFC - HASHES CHECK", " computedHash value: " + convertByteToHexadecimal(computedHash));

                // Verify only DG1 data, could be done for all passport data
			    if (storedHashes != null && storedHashes.size() > 0 && Arrays.equals(storedHashes.get(1), computedHash)) {
					passportDataNotTampered = true;
				} else {
					passportDataNotTampered = false;
				}

              List<FaceImageInfo> allFaceImageInfos = new ArrayList<>();
              List<FaceInfo> faceInfos = dg2File.getFaceInfos();
              for (FaceInfo faceInfo : faceInfos) {
                  allFaceImageInfos.addAll(faceInfo.getFaceImageInfos());
              }

              if (!allFaceImageInfos.isEmpty()) {
                  FaceImageInfo faceImageInfo = allFaceImageInfos.iterator().next();

                  int imageLength = faceImageInfo.getImageLength();
                  DataInputStream dataInputStream = new DataInputStream(faceImageInfo.getImageInputStream());
                  byte[] buffer = new byte[imageLength];
                  dataInputStream.readFully(buffer, 0, imageLength);
                  InputStream inputStream = new ByteArrayInputStream(buffer, 0, imageLength);

                  bitmap = ImageUtil.decodeImage(reactContext, faceImageInfo.getMimeType(), inputStream);

              }

          } catch (Exception e) {
              return e;
          }
          return null;
      }

      @Override
      protected void onPostExecute(Exception result) {
          Log.d("LONG CHECK", "onPostExecute");
          try {
              if (scanPromise == null) return;

              if (result != null) {
                  Log.w(TAG, exceptionStack(result));
                  if (result instanceof IOException) {
                      scanPromise.reject(E_SCAN_FAILED_DISCONNECT, "Lost connection to chip on card");
                  } else {
                      scanPromise.reject(E_SCAN_FAILED, result);
                  }

                  resetState();
                  return;
              }

              MRZInfo mrzInfo = dg1File.getMRZInfo();

              int quality = 100;
              if (opts.hasKey("quality")) {
                  quality = (int) (opts.getDouble("quality") * 100);
              }

              String base64 = toBase64(bitmap, quality);
              WritableMap photo = Arguments.createMap();
              photo.putString("base64", base64);
              photo.putInt("width", bitmap.getWidth());
              photo.putInt("height", bitmap.getHeight());

              String firstName = mrzInfo.getSecondaryIdentifier().replace("<", "");
              String lastName = mrzInfo.getPrimaryIdentifier().replace("<", "");
              WritableMap passport = Arguments.createMap();
              passport.putMap(KEY_PHOTO, photo);
              passport.putString(KEY_FIRST_NAME, firstName);
              passport.putString(KEY_LAST_NAME, lastName);
              passport.putString(KEY_GENDER, mrzInfo.getGender().toString());
              passport.putString(KEY_NATIONALITY, mrzInfo.getNationality());
              passport.putString(KEY_ISSUER, mrzInfo.getIssuingState());
              passport.putString(PERSONAL_NUM, mrzInfo.getPersonalNumber());
              passport.putString(PARAM_DOC_NUM, mrzInfo.getDocumentNumber());
              passport.putString(PARAM_DOB, mrzInfo.getDateOfBirth());
              passport.putString(PARAM_DOE, mrzInfo.getDateOfExpiry());
              passport.putString(MRZ, mrzInfo.toString().replace("\n", ""));
              passport.putString(DSC, documentSigningCertificate);
              passport.putString(DSCV, String.valueOf(documentSigningCertificateVerified));
              passport.putString(PDNT, String.valueOf(passportDataNotTampered));
              
              scanPromise.resolve(passport);
              resetState();
          }catch (Exception e) {}
      }
  }
}

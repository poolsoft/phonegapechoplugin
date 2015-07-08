package com.cem.echo;

    import org.apache.cordova.CordovaPlugin;
    import org.apache.cordova.CallbackContext;

    import org.json.JSONArray;
	import org.json.JSONException;
	import org.json.JSONObject;

	import java.io.File;
	import java.io.InputStream;
	import java.util.ArrayList;
	import java.util.Calendar;
	import java.util.HashMap;
	import java.util.List;

	import javax.smartcardio.CardException;
	import javax.smartcardio.CardTerminal;
	import javax.smartcardio.CardTerminals.State;

	import sun.security.util.PendingException;
	import tr.gov.tubitak.bilgem.uekae.akis.akisCIF.functions.ICommandTransmitter;
	import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
	import tr.gov.tubitak.uekae.esya.api.cmssignature.ISignable;
	import tr.gov.tubitak.uekae.esya.api.cmssignature.SignableFile;
	import tr.gov.tubitak.uekae.esya.api.cmssignature.attribute.EParameters;
	import tr.gov.tubitak.uekae.esya.api.cmssignature.attribute.IAttribute;
	import tr.gov.tubitak.uekae.esya.api.cmssignature.attribute.SigningTimeAttr;
	import tr.gov.tubitak.uekae.esya.api.cmssignature.signature.BaseSignedData;
	import tr.gov.tubitak.uekae.esya.api.cmssignature.signature.ESignatureType;
	import tr.gov.tubitak.uekae.esya.api.common.crypto.Algorithms;
	import tr.gov.tubitak.uekae.esya.api.common.crypto.BaseSigner;
	import tr.gov.tubitak.uekae.esya.api.common.util.LicenseUtil;
	import tr.gov.tubitak.uekae.esya.api.smartcard.android.ccid.reader.SCDTerminalHandler;
	import tr.gov.tubitak.uekae.esya.api.smartcard.apdu.APDUSmartCard;
	import tr.gov.tubitak.uekae.esya.api.smartcard.apdu.TerminalHandler;
	import tr.gov.tubitak.uekae.esya.asn.util.AsnIO;

    /**
     * This class echoes a string called from JavaScript.
     */
    public class Echo extends CordovaPlugin {
		public TerminalHandler mTerminalHandler ;
		public APDUSmartCard mAPDUSmartCard;
		public List<ECertificate> certificateList;
		
		protected String[] getCertificateList() {
			List<String> certs = new ArrayList<String>();
			
			try {
				InputStream lisansStream = cordova.getActivity().getResources().openRawResource(cordova.getActivity().getResources().getIdentifier("lisans", "raw", cordova.getActivity().getPackageName()));
				LicenseUtil.setLicenseXml(lisansStream);
				lisansStream.close();
			
			
			
				mTerminalHandler = new SCDTerminalHandler(cordova.getActivity());
	
				mAPDUSmartCard = new APDUSmartCard(mTerminalHandler);
				mAPDUSmartCard.setDisableSecureMessaging(true);
			
				CardTerminal[] terminalList = mAPDUSmartCard.getTerminalList();
				CardTerminal cardTerminal = terminalList[0];
			
				//System.out.println("hehehe " + terminalList[0]);
			
				mAPDUSmartCard.openSession(cardTerminal);
				String readerName = cardTerminal.getName();
				List<byte[]> signCertValueList = mAPDUSmartCard.getSignatureCertificates();
			
				certificateList=new ArrayList<ECertificate>();
			
				for(byte[] signCertValue:signCertValueList)
				{
					ECertificate signCert = new ECertificate(signCertValue);
					//Sadece nitelikli sertifikalar çekiliyor.
					//Kanuni geçerliliği olmayan sertifikalarla imza atılmak istenirse bu kontrol kaldırılabilir.
					//  if(signCert.isQualifiedCertificate()){
					certificateList.add(signCert);
					System.out.println("Sertifika Sahibi :"+signCert.getSubject().getCommonNameAttribute());
					certs.add(signCert.getSubject().getCommonNameAttribute());
					//}
				}
			} catch(Exception e) {
				return null;
			}
			
			String[] res = new String[ certs.size() ];
			certs.toArray( res );
			return res;
		}
		
		protected boolean sign(int certIndex, String password, String sourceFilePath) {
			try {
				
				String destFilePath = sourceFilePath + ".sgn";
					
				mAPDUSmartCard.login(password);
				
				ECertificate signCert = certificateList.get(certIndex);
				
				BaseSigner signer = mAPDUSmartCard.getSigner(signCert.asX509Certificate(), Algorithms.SIGNATURE_RSA_SHA1);
				BaseSignedData bsd = new BaseSignedData();

				System.out.println("--------------LOGIN BASARILI------------");
				
				ISignable content = new SignableFile(new File(sourceFilePath));
				bsd.addContent(content);
				//Since SigningTime attribute is optional,add it to optional attributes list
				List<IAttribute> optionalAttributes = new ArrayList<IAttribute>();
				optionalAttributes.add(new SigningTimeAttr(Calendar.getInstance()));
				HashMap<String, Object> params = new HashMap<String, Object>();

				params.put(EParameters.P_VALIDATE_CERTIFICATE_BEFORE_SIGNING,false);
				bsd.addSigner(ESignatureType.TYPE_BES, signCert, signer, optionalAttributes, params);
				byte [] signedDocument = bsd.getEncoded();
				System.out.println("İmzalama işlemi tamamlandı. Dosyaya yazılacak. Imzali Veri ="+(signedDocument.toString()));
				
				AsnIO.dosyayaz(signedDocument, destFilePath);
				
				mAPDUSmartCard.logout();
				mAPDUSmartCard.closeSession();
			} catch(Exception e) {
				return false;
			}
			
			return true;
		}
		
        @Override
        public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
			if (action.equals("getCertificateList")) {
			}
			else if(action.equals("sign")) {
			}
            else if (action.equals("echo")) {
                System.out.println("---------hello world----------");
				String message = args.getString(0);
                //this.echo(message, callbackContext);
				
				
				
				try {
					InputStream lisansStream = cordova.getActivity().getResources().openRawResource(cordova.getActivity().getResources().getIdentifier("lisans", "raw", cordova.getActivity().getPackageName()));
					LicenseUtil.setLicenseXml(lisansStream);
					lisansStream.close();
					
					
					
					mTerminalHandler = new SCDTerminalHandler(cordova.getActivity());
			
					mAPDUSmartCard = new APDUSmartCard(mTerminalHandler);
					mAPDUSmartCard.setDisableSecureMessaging(true);
					
					CardTerminal[] terminalList = mAPDUSmartCard.getTerminalList();
					CardTerminal cardTerminal = terminalList[0];
					
					//System.out.println("hehehe " + terminalList[0]);
					
					mAPDUSmartCard.openSession(cardTerminal);
					String readerName = cardTerminal.getName();
					List<byte[]> signCertValueList = mAPDUSmartCard.getSignatureCertificates();
					
					certificateList=new ArrayList<ECertificate>();
					
					for(byte[] signCertValue:signCertValueList)
					{
						ECertificate signCert = new ECertificate(signCertValue);
						//Sadece nitelikli sertifikalar çekiliyor.
						//Kanuni geçerliliği olmayan sertifikalarla imza atılmak istenirse bu kontrol kaldırılabilir.
						//  if(signCert.isQualifiedCertificate()){
						certificateList.add(signCert);
						System.out.println("Sertifika Sahibi :"+signCert.getSubject().getCommonNameAttribute());
						//}
					}
					//handler.sendEmptyMessage(1);
					try
					{
						//Sleep for two seconds
						Thread.sleep(2000);
					}
					catch (InterruptedException e)
					{
						e.printStackTrace(); //webView.loadUrl("javascript:console.log('hello');");
					}
					
					
					// imzala
					
					String sourceFilePath = "file:///storage/emulated/0/Download/udf/Isimsiz.udf", destFilePath;
					
					mAPDUSmartCard.login("");
					ECertificate signCert = certificateList.get(0);
					BaseSigner signer = mAPDUSmartCard.getSigner(signCert.asX509Certificate(), Algorithms.SIGNATURE_RSA_SHA1);
					BaseSignedData bsd = new BaseSignedData();

					System.out.println("--------------LOGIN BASARILI------------");
					
					ISignable content = new SignableFile(new File(sourceFilePath));
					bsd.addContent(content);
					//Since SigningTime attribute is optional,add it to optional attributes list
					List<IAttribute> optionalAttributes = new ArrayList<IAttribute>();
					optionalAttributes.add(new SigningTimeAttr(Calendar.getInstance()));
					HashMap<String, Object> params = new HashMap<String, Object>();

					params.put(EParameters.P_VALIDATE_CERTIFICATE_BEFORE_SIGNING,false);
					bsd.addSigner(ESignatureType.TYPE_BES, signCert, signer, optionalAttributes, params);
					byte [] signedDocument = bsd.getEncoded();
					System.out.println("İmzalama işlemi tamamlandı. Dosyaya yazılacak. Imzali Veri ="+(signedDocument.toString()));
					destFilePath = sourceFilePath+ ".imz";
					//destFilePath = "/sdcard/sdcard0/SignedDoc.imz";
					AsnIO.dosyayaz(signedDocument, destFilePath);
					
					try
					{
						mAPDUSmartCard.logout();
						mAPDUSmartCard.closeSession();
					}
					catch(Exception ex)
					{
						ex.printStackTrace(); //webView.loadUrl("javascript:console.log('hello');");
					}
				}
				catch (Exception e) {
					e.printStackTrace(); //webView.loadUrl("javascript:console.log('hello');");
				}
				
				this.echo(message, callbackContext);
				
				return true;
			}
				
				
				return false;
        }

        private void echo(String message, CallbackContext callbackContext) {
            if (message != null && message.length() > 0) {
                callbackContext.success(message);
            } else {
                callbackContext.error("Expected one non-empty string argument.");
            }
        }
    }

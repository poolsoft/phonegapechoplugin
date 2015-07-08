package com.cem.echo;

    import org.apache.cordova.CordovaPlugin;
    import org.apache.cordova.CallbackContext;
    import android.content.res.Resources;
	import org.apache.cordova.PluginResult;
	import org.apache.cordova.CordovaResourceApi;
	import android.net.Uri;

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
		
		protected boolean getCertificateList(CallbackContext callbackContext) {
			System.out.println("-----getcertlist: entrance");
			
			List<String> certs = new ArrayList<String>();
			
							
			try {
/*				InputStream lisansStream = cordova.getActivity().getResources().openRawResource(cordova.getActivity().getResources().getIdentifier("lisans", "raw", cordova.getActivity().getPackageName()));
				LicenseUtil.setLicenseXml(lisansStream);
				lisansStream.close();*/
				
				Resources activityRes = cordova.getActivity().getResources();
				int lisansid = activityRes.getIdentifier("lisans", "raw", cordova.getActivity().getPackageName());
				InputStream lisansStream = activityRes.openRawResource(lisansid);
				LicenseUtil.setLicenseXml(lisansStream);
				lisansStream.close();
			
				System.out.println("-----getcertlist: lisans aldik");
			
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
				e.printStackTrace();
				PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR);
				pluginResult.setKeepCallback(true);
				callbackContext.sendPluginResult(pluginResult);
				//callbackContext.error("Sertifikaları alırken bir hata oluştu.");
				return false;
			}
			
			String[] res = new String[ certs.size() ];
			certs.toArray( res );
			
			PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, new JSONArray(certs));
			pluginResult.setKeepCallback(true);
			callbackContext.sendPluginResult(pluginResult);
			//callbackContext.success(new JSONArray(certs));
			return true;
		}
		
		protected boolean sign(int certIndex, String password, String sourceFilePath, CallbackContext callbackContext) {
			System.out.println("-----sign: entrance: " + certIndex + " " + password + " " + sourceFilePath );
				cordova.getActivity().runOnUiThread(new Runnable() {
				    public void run() {
				        try {
				
							String destFilePath = sourceFilePath + ".sgn";
					
							mAPDUSmartCard.login(password);
				
							ECertificate signCert = certificateList.get(certIndex);
				
							BaseSigner signer = mAPDUSmartCard.getSigner(signCert.asX509Certificate(), Algorithms.SIGNATURE_RSA_SHA1);
							BaseSignedData bsd = new BaseSignedData();

							System.out.println("--------------LOGIN BASARILI------------");
				
							File tempFile = new File("cem1.txt");
							System.out.println("---temp file: " + tempFile.getAbsolutePath());
				
							CordovaResourceApi resourceApi = webView.getResourceApi();
							Uri sourceUri = resourceApi.remapUri(Uri.fromFile(new File("cem2.txt")));
							System.out.println("---source uri: " + sourceUri);
				
							tempFile = resourceApi.mapUriToFile(Uri.parse(sourceFilePath));
							System.out.println("sourcefilepath....");
							if(tempFile != null) {
								System.out.println(tempFile.getAbsolutePath());
							} else {
								System.out.println("null file");
							}
				
							System.out.println("sourceuri...");
							tempFile = resourceApi.mapUriToFile(sourceUri);
							if(tempFile != null) {
								System.out.println(tempFile.getAbsolutePath());
							} else {
								System.out.println("null file");
							}
				
							ISignable content = new SignableFile(tempFile);
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
							e.printStackTrace();
							PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR);
							pluginResult.setKeepCallback(true);
							callbackContext.sendPluginResult(pluginResult);
							//callbackContext.error("İmzalama sırasında bir hata oluştu. Lütfen şifrenizi kontrol edip tekrar deneyiniz.");
							return false;
						}
			
						PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
						pluginResult.setKeepCallback(true);
						callbackContext.sendPluginResult(pluginResult);
						//callbackContext.success();
						return true;
				    }
				});		
			
		}
		
        @Override
        public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
			if (action.equals("getCertificateList")) {
				System.out.println("-----execute: getcertlist");
				return this.getCertificateList(callbackContext);
			}
			else if(action.equals("sign")) {
				int certIndex = Integer.parseInt(args.getString(0));
				String password = args.getString(1);
				String filepath = args.getString(2);
				return this.sign(certIndex, password, filepath, callbackContext);
			}
				
				
				return false;
        }
    }


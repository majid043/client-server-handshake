
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Client {

	public static void main(String[] args) throws UnknownHostException, IOException, KeyManagementException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException {
		Security.addProvider(new BouncyCastleProvider());
		new Client().startClient();
	}
	
	private KeyStore loadKeyStore(String type, String path, String pass) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException {
		KeyStore keystore = KeyStore.getInstance(type);
		keystore.load(new FileInputStream(new File(path)), pass.toCharArray());
		return keystore;
	}

	private KeyManager[] getKeyManagers() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, KeyStoreException, IOException, UnrecoverableKeyException {
		String pass = "password";
		KeyStore keyStore = loadKeyStore("PKCS12", "keystore.p12", pass);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("sunx509");
		kmf.init(keyStore, pass.toCharArray());
		KeyManager [] km =  kmf.getKeyManagers();
		return km;
	}
	
	private TrustManager[] getTrustManagers() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, KeyStoreException, IOException {
		KeyStore trustStore = loadKeyStore("JKS", "keystore.jks", "password");
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trustStore);
		return tmf.getTrustManagers();
	}

	private void startClient() throws UnknownHostException, IOException, NoSuchAlgorithmException, KeyManagementException, UnrecoverableKeyException, CertificateException, KeyStoreException {
		SSLSocket socket = null;
		String serverIP = "serverip";
		Integer serverPort = 9077;
		int count = 0;
		if (null != serverIP && null != serverPort) {
			System.out.println(" trying to connect with IP " + serverIP + " and port " + serverPort);
			TrustManager[] trustManagers = getTrustManagers();
			KeyManager[] keyManagers = getKeyManagers();
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(keyManagers, trustManagers, null);
			SSLSocketFactory socketFactory = sslContext.getSocketFactory();
			socket = (SSLSocket) socketFactory.createSocket(serverIP,serverPort);
		}
		while ((null != socket && !socket.isClosed()) && count < 10) {
			System.out.println(" Cipher suit used "+socket.getSession().getCipherSuite() );
			try {
				count++;
				if (null != socket && socket.isConnected()) {
					System.out.println(" trying to connect with IP" + serverIP + " and port " + serverPort);
					DataOutputStream dout = new DataOutputStream(socket.getOutputStream());
					dout.writeUTF("Hello Server" + count);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
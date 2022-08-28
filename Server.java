
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Server {

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		new Server().initServer();
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
	
	public void initServer() {
		SSLServerSocket ss = null;
		try {
			TrustManager[] trustManagers = getTrustManagers();
			KeyManager[] keyManagers = getKeyManagers();
			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(keyManagers, trustManagers, null);
			ss =(SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(9077);

			System.out.println("Server is Up and listening ....");
			SSLSocket clinetSocket = (SSLSocket) ss.accept();
			System.out.println("IP of client socket is "+clinetSocket.getInetAddress().getHostAddress() + " Port is "+ clinetSocket.getPort());
			while ((null != clinetSocket && !clinetSocket.isClosed())) {
				System.out.println(" Cipher suit used "+ clinetSocket.getEnabledCipherSuites());
				DataInputStream dis = new DataInputStream(clinetSocket.getInputStream());
				String str = (String) dis.readUTF();
				System.out.println("Client message= " + str);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
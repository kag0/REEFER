package ui;
//REEFER Emboldened Encryption For Every Rager
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.UIManager;

import net.miginfocom.swing.MigLayout;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JButton;
import javax.swing.SwingWorker;

import blackdoor.util.Hash;
import blackdoor.util.Misc;
import blackdoor.util.SHE;
import blackdoor.util.SHE.EncryptionResult;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

public class MainUI {

	private JFrame frmReefer;
	private JTextField txtPlainFileLocation;
	private JTextField txtCipherFileLocation;
	private JPasswordField pwdPassword;
	private JTextField txtPlainHash;
	private JTextField txtCipherHash;
	private JLabel lblDone;
	private JButton btnEncrypt;
	private JButton btnDecrypt;
	private final String defaultPasswordText = "password needs to be long";
	private final String defaultInputFileText = "Plaintext file location";
	private final String defaultOutputFileText = "Ciphertext file location";
	private final JFileChooser fc = new JFileChooser();
	private File plainFile;
	private File cipherFile;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		} catch (Throwable e) {
			e.printStackTrace();
		}
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainUI window = new MainUI();
					window.frmReefer.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	private byte[] getHashedKey(){
		return Hash.getSHA256(
				new String(pwdPassword.getPassword()).getBytes(StandardCharsets.US_ASCII));
	}

	/**
	 * 
	 * @param hashesToUpdate index 0 is the inputfile, index 1 is the output file
	 */
	private void updateHashes(boolean[] hashesToUpdate) {
		if (hashesToUpdate[0]) {
			try {
				txtPlainHash.setText(Misc.bytesToHex(Hash.getFileHash(plainFile)));
			} catch (IOException e) {
				txtPlainHash.setText("Invalid File.");
			}
		}
		if (hashesToUpdate[1]) {
			try {
				txtCipherHash
						.setText(Misc.bytesToHex(Hash.getFileHash(cipherFile)));
			} catch (IOException e) {
				txtCipherHash.setText("Invalid File.");
			}
		}
	}
	
	private void encrypt() throws Exception{
		if(plainFile == null || !plainFile.exists() || cipherFile == null)
			throw new Exception("files not set up");
		SHE cipher = new SHE();
		byte[] IV = cipher.init(getHashedKey());
		byte[] plainText = Files.readAllBytes(plainFile.toPath());
		EncryptionResult out = new EncryptionResult(cipher.doFinal(plainText), IV);
		txtCipherHash.setText(Misc.bytesToHex(Hash.getSHA256(out.simpleSerial())));
		plainText = null;
		FileOutputStream fw = new FileOutputStream(cipherFile);
		fw.write(out.simpleSerial());
		fw.close();
		//System.out.println(out);
		//System.out.println(Misc.bytesToHex(out.simpleSerial()));
	}
	
	
	
	private void threadedBufferedEncrypt(){
		SwingWorker<Integer, Integer> worker = new SwingWorker<Integer, Integer>() {
		    @Override
		    public Integer doInBackground() throws Exception {
		    	if(plainFile == null || !plainFile.exists() || cipherFile == null)
					throw new Exception("files not set up");
				//create buffered reader and writer
				FileInputStream fis = new FileInputStream(plainFile);
				BufferedInputStream inStream = new BufferedInputStream(fis);
				FileOutputStream fos = new FileOutputStream(cipherFile);
				BufferedOutputStream outStream = new BufferedOutputStream(fos);
				//create new cipher and IV
				SHE cipher = new SHE();
				byte[] IV = cipher.init(getHashedKey());
				//System.out.println(Misc.bytesToHex(IV));
				byte[] buffer = new byte[IV.length];
				//write IV.length and IV to file
				byte[] len = new byte[]{(byte) IV.length};
				outStream.write(len);
				outStream.write(IV);
				//buffer = first 32 bytes of reader
				//while reader is not at EOF
				int k;
				int block = 0;
				int percent = 0;
				while((k = inStream.read(buffer)) != -1){//buffer = next 32 bytes of reader
					//write cipher.update(buffer) to file
					outStream.write(cipher.update(Arrays.copyOf(buffer, k)));
					if(percent != (percent = (int) (((float) block++)/(plainFile.length()/IV.length)*100)) && percent % 2 == 0){
						process(percent);
						//System.out.println(percent);
						//lblDone.setText(percent + "%");//System.out.println((percent = (int) (((float) block++)/(inFile.length()/IV.length)*100)) + "% done.");
					}
						
				}
				
				//write cipher.doFinal(buffer) to file
				outStream.write(cipher.doFinal());
				inStream.close();
				outStream.flush();
				outStream.close();
		    	return 0;
		    }

		    protected void process(int percent){
		    	lblDone.setText(percent + "%");
		    }
		    protected void done(){
		    	toggleEDEnable();
		    }
		};
		
		worker.execute();
	}
	private void bufferedEncrypt() throws Exception{
		if(plainFile == null || !plainFile.exists() || cipherFile == null)
			throw new Exception("files not set up");
		//create buffered reader and writer
		FileInputStream fis = new FileInputStream(plainFile);
		BufferedInputStream inStream = new BufferedInputStream(fis);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		BufferedOutputStream outStream = new BufferedOutputStream(fos);
		//create new cipher and IV
		SHE cipher = new SHE();
		byte[] IV = cipher.init(getHashedKey());
		
		byte[] buffer = new byte[IV.length];
		//write IV.length and IV to file
		byte[] len = new byte[]{(byte) IV.length};
		outStream.write(len);
		outStream.write(IV);
		//buffer = first 32 bytes of reader
		//while reader is not at EOF
		int k;
		int block = 0;
		int percent = 0;
		while((k = inStream.read(buffer)) != -1){//buffer = next 32 bytes of reader
			//write cipher.update(buffer) to file
			outStream.write(cipher.update(Arrays.copyOf(buffer, k)));
			if(percent != (percent = (int) (((float) block++)/(plainFile.length()/IV.length)*100)) && percent % 2 == 0){
				System.out.println(percent);
				lblDone.setText(percent + "%");//System.out.println((percent = (int) (((float) block++)/(inFile.length()/IV.length)*100)) + "% done.");
			}
				
		}
		
		//write cipher.doFinal(buffer) to file
		outStream.write(cipher.doFinal());
		inStream.close();
		outStream.close();
		//txtCipherHash.setText(Misc.bytesToHex(Hash.getFileHash(cipherFile)));
	}
	private void threadedBufferedDecrypt(){
		SwingWorker<Integer, Integer> worker = new SwingWorker<Integer, Integer>() {
		    @Override
		    public Integer doInBackground() throws Exception {
		    	if(plainFile == null || !cipherFile.exists() || cipherFile == null)
					throw new Exception("files not set up");
				//create buffered reader and writer
				FileInputStream fis = new FileInputStream(cipherFile);
				BufferedInputStream inStream = new BufferedInputStream(fis);
				FileOutputStream fos = new FileOutputStream(plainFile);
				BufferedOutputStream outStream = new BufferedOutputStream(fos);

				//create new cipher and IV
				SHE cipher = new SHE();
				
				//read IV length and IV from file
				int len = inStream.read();
				byte[] IV = new byte[len];
				inStream.read(IV);

				cipher.init(IV, getHashedKey());
				byte[] buffer = new byte[IV.length];

				int k;
				int block = 0;
				int percent = 0;
				while((k = inStream.read(buffer)) != -1){//buffer = next 32 bytes of reader
					byte[] debug;
					if((block+1)*32 >= (cipherFile.length()-IV.length-1))
						debug = cipher.doFinal(Arrays.copyOf(buffer, k));
					else debug = cipher.update(Arrays.copyOf(buffer, k));

					fos.write(debug);
					if(percent != (percent = (int) (((float) block++)/(cipherFile.length()/IV.length)*100)) && percent % 2 == 0){
						process(percent);
						//System.out.println(percent);
						//lblDone.setText(percent + "%");//System.out.println((percent = (int) (((float) block++)/(inFile.length()/IV.length)*100)) + "% done.");
					}
						
				}
				
				//write cipher.doFinal(buffer) to file
				//outStream.write(cipher.doFinal());
				process(100);
				inStream.close();
				outStream.close();
		    	return 0;
		    }

		    protected void process(int percent){
		    	lblDone.setText(percent + "%");
		    }
		    
		    protected void done(){
		    	toggleEDEnable();
		    }
		};
		
		worker.execute();
	}
	private void decrypt() throws Exception{
		if(plainFile == null || !plainFile.exists() || cipherFile == null)
			throw new Exception("files not set up");
		SHE cipher = new SHE();
		//System.out.println(Misc.bytesToHex(Files.readAllBytes(inFile.toPath())));
		EncryptionResult in = new EncryptionResult(Files.readAllBytes(plainFile.toPath()));
		//System.out.println(in);
		cipher.init(in.getIv(), getHashedKey());
		FileOutputStream fw = new FileOutputStream(cipherFile);
		byte[] out = cipher.doFinal(in.getText());
		fw.write(out);
		fw.close();
		txtCipherHash.setText(Misc.bytesToHex(Hash.getSHA256(out)));
	}

	/**
	 * Create the application.
	 */
	public MainUI() {
		initialize();
	}

	private void toggleEDEnable(){
		btnEncrypt.setEnabled(!btnEncrypt.isEnabled());
		btnDecrypt.setEnabled(!btnDecrypt.isEnabled());
	}
	
	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmReefer = new JFrame();
		frmReefer.setTitle("REEFER Emboldened Encryption For Every Rager");
		frmReefer.setBounds(100, 100, 450, 176);
		frmReefer.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmReefer.getContentPane().setLayout(new MigLayout("", "[][grow]", "[][][][][][]"));
		
		JLabel lblPlainFile = new JLabel("Plaintext file:");
		frmReefer.getContentPane().add(lblPlainFile, "cell 0 0,alignx trailing");
		
		txtPlainFileLocation = new JTextField();
		txtPlainFileLocation.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent arg0) {
				 plainFile = new File(txtPlainFileLocation.getText());
				 if(plainFile.exists()){
		            //try {
						//txtPlainHash.setText(Misc.bytesToHex(Hash.getFileHash(plainFile)));
					//} catch (IOException e1) {
					//	System.err.println("File not valid");
					//	e1.printStackTrace();
					//}
				 }
				 else txtPlainHash.setText("invalid file");
			}
		});

		txtPlainFileLocation.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if(defaultInputFileText.equals(new String(txtPlainFileLocation.getText())))
					txtPlainFileLocation.setText("");
			}
		});
		txtPlainFileLocation.setText(defaultInputFileText);
		frmReefer.getContentPane().add(txtPlainFileLocation, "flowx,cell 1 0,growx");
		txtPlainFileLocation.setColumns(10);
		
		JLabel lblCipherFile = new JLabel("Ciphertext file:");
		frmReefer.getContentPane().add(lblCipherFile, "cell 0 1,alignx trailing");
		
		txtCipherFileLocation = new JTextField();
		txtCipherFileLocation.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				 cipherFile = new File(txtCipherFileLocation.getText());
			}
		});
		txtCipherFileLocation.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if(defaultOutputFileText.equals(new String(txtCipherFileLocation.getText())))
					txtCipherFileLocation.setText("");
			}
		});
		txtCipherFileLocation.setText(defaultOutputFileText);
		frmReefer.getContentPane().add(txtCipherFileLocation, "flowx,cell 1 1,growx");
		txtCipherFileLocation.setColumns(10);
		
		lblDone = new JLabel("");
		frmReefer.getContentPane().add(lblDone, "cell 0 2,alignx center");
		
		JLabel lblPlainHash = new JLabel("Plaintext hash:");
		frmReefer.getContentPane().add(lblPlainHash, "flowx,cell 1 2");
		
		JLabel lblPassword = new JLabel("Password:");
		frmReefer.getContentPane().add(lblPassword, "cell 0 3,alignx trailing");
		
		pwdPassword = new JPasswordField();
		pwdPassword.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				if(defaultPasswordText.equals(new String(pwdPassword.getPassword())))
					pwdPassword.setText("");
			}
		});
		pwdPassword.setText(defaultPasswordText);
		frmReefer.getContentPane().add(pwdPassword, "cell 1 3,growx");
		
		JButton btnSelectFilePlain = new JButton("Select file");
		btnSelectFilePlain.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				int returnVal = fc.showOpenDialog(frmReefer);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
		            plainFile = fc.getSelectedFile();
		            txtPlainFileLocation.setText(plainFile.getAbsolutePath());
		            //try {
					//	//txtPlainHash.setText(Misc.bytesToHex(Hash.getFileHash(plainFile)));
					//} catch (IOException e1) {
					//	System.err.println("File not valid");
					//	e1.printStackTrace();
					//}
		            System.out.println(plainFile.getName());
				}
				
			}
		});
		frmReefer.getContentPane().add(btnSelectFilePlain, "cell 1 0");
		
		JButton btnSelectFileCipher = new JButton("Select file");
		btnSelectFileCipher.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				int returnVal = fc.showSaveDialog(frmReefer);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
		            cipherFile = fc.getSelectedFile();
		            txtCipherFileLocation.setText(cipherFile.getAbsolutePath());
				}
			}
		});
	
		frmReefer.getContentPane().add(btnSelectFileCipher, "cell 1 1");
		
		txtPlainHash = new JTextField();
		frmReefer.getContentPane().add(txtPlainHash, "cell 1 2,growx");
		txtPlainHash.setColumns(10);
		
		JLabel lblCipherHash = new JLabel("Ciphertext hash:");
		frmReefer.getContentPane().add(lblCipherHash, "cell 1 2");
		
		txtCipherHash = new JTextField();
		frmReefer.getContentPane().add(txtCipherHash, "cell 1 2,growx");
		txtCipherHash.setColumns(10);
		
		btnEncrypt = new JButton("Encrypt");
		btnEncrypt.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				try {
					toggleEDEnable();
					threadedBufferedEncrypt();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				//updateHashes(new boolean[]{false, true});
			}
		});
		
		JButton btnRefreshHashes = new JButton("Refresh Hashes");
		btnRefreshHashes.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				updateHashes(new boolean[]{true, true});
			}
		});
		frmReefer.getContentPane().add(btnRefreshHashes, "flowx,cell 1 4,alignx right");
		frmReefer.getContentPane().add(btnEncrypt, "cell 1 4,alignx right");
		
		btnDecrypt = new JButton("Decrypt");
		btnDecrypt.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					toggleEDEnable();
					threadedBufferedDecrypt();
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				//updateHashes(new boolean[]{false, true});
			}
		});
		frmReefer.getContentPane().add(btnDecrypt, "cell 1 4,alignx right");
	}

}

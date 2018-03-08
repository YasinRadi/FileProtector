/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package fileprotector.gui;

import fileprotector.exceptions.DecryptingException;
import fileprotector.decrypt.Decrypter;
import fileprotector.encrypt.Encrypter;
import fileprotector.utils.Utils;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileSystemView;

/**
 *
 * @author Yasin Radi
 */
public class FileProtector extends javax.swing.JFrame {

    /**
     * Encrypted Files Directory.
     */
    public final static String FILE_PATH = FileSystemView.getFileSystemView().getDefaultDirectory().getPath() + "\\FileProtector\\";

    /**
     * Encrypter object.
     */
    private final Encrypter encrypter = new Encrypter();

    /**
     * Decrypter object.
     */
    private final Decrypter decrypter = new Decrypter();

    /**
     * File Chooser.
     */
    private final JFileChooser browser = new JFileChooser();

    /**
     * Files to be encrypted or decrypted.
     */
    private File[] files;

    /**
     * Creates new form FileProtector
     * @throws IOException
     */
    public FileProtector() throws IOException {
        initComponents();
        this.setTitle("File Protector");
        this.setLocationRelativeTo(null);
        this.browser.setMultiSelectionEnabled(true);
        if(!new File(FileProtector.FILE_PATH).exists()) new File(FileProtector.FILE_PATH).mkdirs();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jFileChooser1 = new javax.swing.JFileChooser();
        lblFile = new javax.swing.JLabel();
        lblPass = new javax.swing.JLabel();
        tfPass = new javax.swing.JPasswordField();
        btnEncrypt = new javax.swing.JButton();
        btnDecrypt = new javax.swing.JButton();
        btnBrowse = new javax.swing.JButton();
        tfPath = new javax.swing.JTextField();
        tfPassConfirm = new javax.swing.JPasswordField();
        jLabel1 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        lblFile.setText("File: ");

        lblPass.setText("Input Password: ");

        btnEncrypt.setText("Encrypt");
        btnEncrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEncryptActionPerformed(evt);
            }
        });

        btnDecrypt.setText("Decrypt");
        btnDecrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDecryptActionPerformed(evt);
            }
        });

        btnBrowse.setText("Browse");
        btnBrowse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBrowseActionPerformed(evt);
            }
        });

        tfPath.setEnabled(false);

        jLabel1.setText("Confirm Password: ");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(lblFile)
                    .addComponent(jLabel1)
                    .addComponent(lblPass))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(tfPath, javax.swing.GroupLayout.DEFAULT_SIZE, 184, Short.MAX_VALUE)
                        .addGap(18, 18, 18)
                        .addComponent(btnBrowse))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(tfPassConfirm, javax.swing.GroupLayout.DEFAULT_SIZE, 198, Short.MAX_VALUE)
                            .addComponent(tfPass))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(75, 75, 75)
                .addComponent(btnEncrypt)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(btnDecrypt)
                .addGap(65, 65, 65))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(32, 32, 32)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnBrowse)
                    .addComponent(lblFile)
                    .addComponent(tfPath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(26, 26, 26)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tfPass, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lblPass))
                .addGap(27, 27, 27)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tfPassConfirm, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 22, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnEncrypt)
                    .addComponent(btnDecrypt))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnBrowseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBrowseActionPerformed

        int result = this.browser.showOpenDialog(this);
        if (result == JFileChooser.OPEN_DIALOG) {
            this.files = this.browser.getSelectedFiles();
            String s = "";
            for (File f : this.getFiles()) {
                s += " \"" + f.getName() + "\", ";
            }
            if (!s.isEmpty()) {
                s = s.substring(0, s.length() - 1);
            }
            this.tfPath.setText(s);
        }

    }//GEN-LAST:event_btnBrowseActionPerformed

    private void btnEncryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEncryptActionPerformed
        try {
            /**
             * If passwords are not blank.
             */
            if (Utils.passwordNotEmpty(Utils.charArrayToString(this.tfPass.getPassword()),
                Utils.charArrayToString(this.tfPassConfirm.getPassword()))) 
            {
                /**
                 * If passwords match.
                 */
                if (Utils.passwordCheck(Utils.charArrayToString(this.tfPass.getPassword()),
                    Utils.charArrayToString(this.tfPassConfirm.getPassword()))) 
                {
                    for (File f : this.getFiles()) {
                        this.encrypter.encryptFile(f, Utils.charArrayToString(this.tfPass.getPassword()));
                        /**
                         * Delete original file once encrypted.
                         */
                        f.delete();
                    }

                    JOptionPane.showMessageDialog(null, "Encryption Complete.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    clear();
                } else {
                    JOptionPane.showMessageDialog(null, "Password fields must match.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(null, "Password fields cannot be blank.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } catch (NullPointerException e1) {
            JOptionPane.showMessageDialog(null, "No File has been selected.", "Warning", JOptionPane.WARNING_MESSAGE);
        } catch (Exception ex) {
            Logger.getLogger(FileProtector.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }//GEN-LAST:event_btnEncryptActionPerformed

    private void btnDecryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDecryptActionPerformed
        try {
            /**
             * If passwords are not blank.
             */
            if (Utils.passwordNotEmpty(Utils.charArrayToString(this.tfPass.getPassword()),
                Utils.charArrayToString(this.tfPassConfirm.getPassword()))) 
            {
                /**
                 * If passwords match.
                 */
                if (Utils.passwordCheck(Utils.charArrayToString(this.tfPass.getPassword()),
                    Utils.charArrayToString(this.tfPassConfirm.getPassword()))) 
                {
                    for (File f : this.getFiles()) {
                        this.decrypter.decrypt(f, Utils.charArrayToString(this.tfPass.getPassword()));
                    }

                    JOptionPane.showMessageDialog(null, "Decryption Complete.", "Success", JOptionPane.INFORMATION_MESSAGE);
                    clear();
                } else {
                    JOptionPane.showMessageDialog(null, "Password fields must match.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(null, "Password fields cannot be blank.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } catch (NullPointerException e1) {
            JOptionPane.showMessageDialog(null, "No File has been selected.", "Warning", JOptionPane.WARNING_MESSAGE);
        } catch (DecryptingException e2) {
            JOptionPane.showMessageDialog(null, "Incorrect Password.", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (Exception e) {
            Logger.getLogger(FileProtector.class.getName()).log(Level.SEVERE, null, e);
        }
    }//GEN-LAST:event_btnDecryptActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(FileProtector.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(FileProtector.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(FileProtector.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FileProtector.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(() -> {
            try {
                new FileProtector().setVisible(true);
            } catch (IOException ex) {
                Logger.getLogger(FileProtector.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
    }

    public File[] getFiles() {
        return files;
    }

    public void setFiles(File[] files) {
        this.files = files;
    }

    /**
     * Clears text fields.
     */
    private void clear() {
        this.setFiles(null);
        this.tfPass.setText("");
        this.tfPassConfirm.setText("");
        this.tfPath.setText("");
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnBrowse;
    private javax.swing.JButton btnDecrypt;
    private javax.swing.JButton btnEncrypt;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel lblFile;
    private javax.swing.JLabel lblPass;
    private javax.swing.JPasswordField tfPass;
    private javax.swing.JPasswordField tfPassConfirm;
    private javax.swing.JTextField tfPath;
    // End of variables declaration//GEN-END:variables
}

package id.encpictaes;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

//import com.scottyab.aescrypt.AESCrypt;

import java.security.GeneralSecurityException;
import java.util.Objects;

public class MainActivity3 extends AppCompatActivity {

    EditText passwordBox;
    EditText messageBox;
    Button decryptBtn;
    Button encryptBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main3);
        passwordBox = findViewById(R.id.passwordBox);
        messageBox = findViewById(R.id.messageBox);
        decryptBtn = findViewById(R.id.decrBtn);
        encryptBtn = findViewById(R.id.encBtn);

        decryptBtn.setOnClickListener(view -> {
            try {
                String messageAfterDecrypt = AESCryptt.decrypt(passwordBox.getText().toString(), messageBox.getText().toString());
                messageBox.setText(messageAfterDecrypt);
            }catch (GeneralSecurityException e){
                Log.e("Mainact3","error dec : "+e.getMessage());
                if(Objects.requireNonNull(e.getMessage()).contains("BAD_DECRYPT")) {
                    Toast.makeText(this, "Password anda salah", Toast.LENGTH_LONG).show();
                }
            }
        });

        encryptBtn.setOnClickListener(view -> {
            try {
                String encryptedMsg = AESCryptt.encrypt(passwordBox.getText().toString(), messageBox.getText().toString());
                messageBox.setText(encryptedMsg);
            }catch (GeneralSecurityException e){
                Log.e("Mainact3","error enc : "+e.getMessage());
                if(Objects.requireNonNull(e.getMessage()).contains("BAD_DECRYPT")) {
                    Toast.makeText(this, "Password anda salah", Toast.LENGTH_LONG).show();
                }
            }
        });
    }
}
package id.encpictaes;

import androidx.appcompat.app.AppCompatActivity;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.media.Image;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Objects;

public class MainActivity4 extends AppCompatActivity {

    EditText passwordBox;
    ImageView imageIV;
    TextView textImage;
    Button decryptBtn;
    Button encryptBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main4);

        imageIV = findViewById(R.id.imageIV);
        textImage = findViewById(R.id.textImage);

        passwordBox = findViewById(R.id.passwordBox);

        decryptBtn = findViewById(R.id.decrBtn);
        encryptBtn = findViewById(R.id.encBtn);

        decryptBtn.setOnClickListener(view -> {
            try {
                byte[] messageAfterDecrypt = AESCryptt.decryptt(passwordBox.getText().toString(), textImage.getText().toString());

                //convertStringOrHexToImage
                Bitmap bmp = BitmapFactory.decodeByteArray(messageAfterDecrypt, 0, messageAfterDecrypt.length);

                imageIV.setImageBitmap(bmp);
                textImage.setText("");
            } catch (GeneralSecurityException e) {
                Log.e("Mainact3", "error dec : " + e.getMessage());
                if (Objects.requireNonNull(e.getMessage()).contains("BAD_DECRYPT")) {
                    Toast.makeText(this, "Password anda salah", Toast.LENGTH_LONG).show();
                }
            }
        });

        encryptBtn.setOnClickListener(view -> {
            String imageStr = imageToString(imageIV);
            imageIV.invalidate();
            imageIV.setImageBitmap(null);
            try {
                String encryptedMsg = AESCryptt.encrypt(passwordBox.getText().toString(), imageStr);
                textImage.setText(encryptedMsg);
            } catch (GeneralSecurityException e) {
                Log.e("Mainact3", "error enc : " + e.getMessage());
                if (Objects.requireNonNull(e.getMessage()).contains("BAD_DECRYPT")) {
                    Toast.makeText(this, "Password anda salah", Toast.LENGTH_LONG).show();
                }
            }
        });
    }

    public String imageToString(ImageView iv) {

        iv.buildDrawingCache();
        Bitmap bmap = iv.getDrawingCache();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        bmap.compress(Bitmap.CompressFormat.JPEG, 100, stream);
        byte[] imageInByte = stream.toByteArray();

        return bytesToHex(imageInByte);
    }

    private static String bytesToHex(byte[] bytes) {
        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
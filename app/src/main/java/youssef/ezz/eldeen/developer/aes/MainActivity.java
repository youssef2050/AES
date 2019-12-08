package youssef.ezz.eldeen.developer.aes;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.security.GeneralSecurityException;

public class MainActivity extends AppCompatActivity {
    EditText massage, key;
    TextView result;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        StatusBarStyle(getWindow());
        massage = findViewById(R.id.massage);
        key = findViewById(R.id.key);
        result = findViewById(R.id.result);

    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void decrypt(View view) throws GeneralSecurityException,Exception {
        String massage = this.massage.getText().toString().trim();
        String key = this.key.getText().toString().trim();
        if (!TextUtils.isEmpty(massage) && !TextUtils.isEmpty(key))
            result.setText(AESCrypt.decrypt(key, massage));
        else
            Toast.makeText(this, getResources().getText(R.string.massageIsEmpty), Toast.LENGTH_SHORT).show();

    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void encrypt(View view) throws GeneralSecurityException {
        String massage = this.massage.getText().toString().trim();
        String key = this.key.getText().toString().trim();
        if (!TextUtils.isEmpty(massage) && !TextUtils.isEmpty(key))
            result.setText(AESCrypt.encrypt(key, massage));
        else
            Toast.makeText(this, getResources().getText(R.string.massageIsEmpty), Toast.LENGTH_SHORT).show();

    }

    private void StatusBarStyle(Window w) {
        w.setFlags(WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS, WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS);
    }

    public void copy(View view) {
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("simple text",result.getText().toString());
        assert cm != null;
        cm.setPrimaryClip(clip);
        Toast.makeText(this, getResources().getText(R.string.copy), Toast.LENGTH_SHORT).show();
    }
}

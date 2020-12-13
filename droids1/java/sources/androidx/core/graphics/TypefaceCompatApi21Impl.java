package androidx.core.graphics;

import android.content.Context;
import android.graphics.Typeface;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.core.provider.FontsContractCompat.FontInfo;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@RequiresApi(21)
@RestrictTo({Scope.LIBRARY_GROUP})
class TypefaceCompatApi21Impl extends TypefaceCompatBaseImpl {
    private static final String TAG = "TypefaceCompatApi21Impl";

    TypefaceCompatApi21Impl() {
    }

    private File getFile(ParcelFileDescriptor fd) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("/proc/self/fd/");
            sb.append(fd.getFd());
            String path = Os.readlink(sb.toString());
            if (OsConstants.S_ISREG(Os.stat(path).st_mode)) {
                return new File(path);
            }
            return null;
        } catch (ErrnoException e) {
            return null;
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:42:0x005f, code lost:
        r4 = th;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:43:0x0060, code lost:
        r5 = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:47:0x0064, code lost:
        r5 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:48:0x0065, code lost:
        r9 = r5;
        r5 = r4;
        r4 = r9;
     */
    /* JADX WARNING: Failed to process nested try/catch */
    /* JADX WARNING: Removed duplicated region for block: B:42:0x005f A[ExcHandler: all (th java.lang.Throwable), Splitter:B:6:0x001a] */
    public Typeface createFromFontInfo(Context context, CancellationSignal cancellationSignal, @NonNull FontInfo[] fonts, int style) {
        ParcelFileDescriptor pfd;
        Throwable th;
        Throwable th2;
        FileInputStream fis;
        Throwable th3;
        Throwable th4;
        if (fonts.length < 1) {
            return null;
        }
        FontInfo bestFont = findBestInfo(fonts, style);
        try {
            pfd = context.getContentResolver().openFileDescriptor(bestFont.getUri(), "r", cancellationSignal);
            try {
                File file = getFile(pfd);
                if (file != null) {
                    if (file.canRead()) {
                        Typeface createFromFile = Typeface.createFromFile(file);
                        if (pfd != null) {
                            pfd.close();
                        }
                        return createFromFile;
                    }
                }
                fis = new FileInputStream(pfd.getFileDescriptor());
                try {
                    Typeface createFromInputStream = super.createFromInputStream(context, fis);
                    fis.close();
                    if (pfd != null) {
                        pfd.close();
                    }
                    return createFromInputStream;
                } catch (Throwable th5) {
                    Throwable th6 = th5;
                    th3 = r6;
                    th4 = th6;
                }
            } catch (Throwable th7) {
            }
        } catch (IOException e) {
            return null;
        }
        if (th3 != null) {
            fis.close();
        } else {
            fis.close();
        }
        throw th4;
        throw th2;
        if (pfd != null) {
            if (th != null) {
                try {
                    pfd.close();
                } catch (Throwable th8) {
                    th.addSuppressed(th8);
                }
            } else {
                pfd.close();
            }
        }
        throw th2;
        throw th4;
    }
}

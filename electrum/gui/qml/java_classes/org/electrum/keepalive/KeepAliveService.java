package org.electrum.keepalive;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.Log;

/**
 * Foreground service whose only purpose is to keep the app process alive
 * (exempt from cached-app freezing/killing) while Electrum waits for an event
 * it can handle in the background, e.g. an incoming lightning payment for a
 * payment request the user is displaying.
 *
 * The service runs in the main app process (no android:process attribute in
 * the manifest entry, see --native-service in buildozer_qml.spec), so the
 * Python threads keep running while it is active. It is started and stopped
 * from Python (qeapp.py) via Context.startForegroundService()/stopService().
 * As a safety net against missed stop conditions, the service stops itself
 * after the timeout passed in EXTRA_TIMEOUT_SECONDS.
 */
public class KeepAliveService extends Service {
    private static final String TAG = "electrum.KeepAliveService";

    // all extras are string extras, as pyjnius overload selection for
    // putExtra(String, int) vs putExtra(String, long) is not deterministic
    public static final String EXTRA_MESSAGE = "message";
    public static final String EXTRA_CHANNEL_NAME = "channel_name";
    public static final String EXTRA_TIMEOUT_SECONDS = "timeout_s";

    private static final String NOTIFICATION_CHANNEL_ID = "electrum_keepalive";
    private static final int NOTIFICATION_ID = 1;
    private static final int MAX_TIMEOUT_SECONDS = 24 * 60 * 60;

    // wall-clock deadline; Handler.postDelayed alone runs on uptimeMillis, which
    // does not advance in deep sleep, so the runnable re-checks this and re-posts
    private long deadlineMillis;

    private final Handler timeoutHandler = new Handler(Looper.getMainLooper());
    private final Runnable timeoutRunnable = new Runnable() {
        @Override
        public void run() {
            long remaining = deadlineMillis - System.currentTimeMillis();
            if (remaining > 1000) {
                timeoutHandler.postDelayed(this, remaining);
                return;
            }
            Log.i(TAG, "timeout reached, stopping service");
            stopSelf();
        }
    };

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String message = null;
        String channelName = null;
        int timeoutSeconds = MAX_TIMEOUT_SECONDS;
        if (intent != null) {
            message = intent.getStringExtra(EXTRA_MESSAGE);
            channelName = intent.getStringExtra(EXTRA_CHANNEL_NAME);
            String timeoutStr = intent.getStringExtra(EXTRA_TIMEOUT_SECONDS);
            if (timeoutStr != null) {
                try {
                    timeoutSeconds = Integer.parseInt(timeoutStr);
                } catch (NumberFormatException e) {
                    Log.w(TAG, "invalid timeout extra: " + timeoutStr);
                }
            }
        }
        if (message == null) {
            message = "Running in background";
        }
        if (channelName == null) {
            channelName = "Waiting for payment";
        }
        if (timeoutSeconds <= 0 || timeoutSeconds > MAX_TIMEOUT_SECONDS) {
            timeoutSeconds = MAX_TIMEOUT_SECONDS;
        }

        Notification notification = buildNotification(message, channelName);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }

        deadlineMillis = System.currentTimeMillis() + timeoutSeconds * 1000L;
        timeoutHandler.removeCallbacks(timeoutRunnable);
        timeoutHandler.postDelayed(timeoutRunnable, timeoutSeconds * 1000L);
        Log.i(TAG, "started, timeout in " + timeoutSeconds + "s");
        return START_NOT_STICKY;
    }

    private int getSmallIconRes() {
        // the application icon (@mipmap/icon) resolves to the adaptive launcher
        // icon, which status bar icons render as a solid blob (they are alpha
        // masked); the foreground layer png p4a installs has a real alpha channel
        int iconRes = getResources().getIdentifier("icon_foreground", "mipmap", getPackageName());
        return iconRes != 0 ? iconRes : getApplicationInfo().icon;
    }

    private Notification buildNotification(String message, String channelName) {
        // minSdk is 26, so notification channels are always available.
        // createNotificationChannel is idempotent (and updates the name).
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationChannel channel = new NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                channelName,
                NotificationManager.IMPORTANCE_LOW);  // silent, but visible in the shade
        channel.setShowBadge(false);
        manager.createNotificationChannel(channel);

        Notification.Builder builder = new Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setContentTitle("Electrum")
                .setContentText(message)
                .setSmallIcon(getSmallIconRes())
                .setOngoing(true)
                .setShowWhen(false)
                .setCategory(Notification.CATEGORY_SERVICE);
        Intent launchIntent = getPackageManager().getLaunchIntentForPackage(getPackageName());
        if (launchIntent != null) {
            builder.setContentIntent(PendingIntent.getActivity(
                    this, 0, launchIntent, PendingIntent.FLAG_IMMUTABLE));
        }
        return builder.build();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        // the user dismissed the app from recents; don't outlive it
        stopSelf();
    }

    @Override
    public void onDestroy() {
        timeoutHandler.removeCallbacks(timeoutRunnable);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}

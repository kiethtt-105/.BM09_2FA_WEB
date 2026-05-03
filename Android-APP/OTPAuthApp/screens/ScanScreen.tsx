import React, { useState } from 'react';
import { View, Text, StyleSheet, Alert, TouchableOpacity } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as SecureStore from 'expo-secure-store';
import * as OTPAuth from 'otpauth';

export default function ScanScreen({ navigation, route }: any) {
  const [scanned, setScanned] = useState(false);
  const [permission, requestPermission] = useCameraPermissions();

  // Chưa cấp quyền camera
  if (!permission) {
    return <View style={styles.container} />;
  }

  if (!permission.granted) {
    return (
      <View style={styles.center}>
        <Text style={styles.permText}>Cần quyền truy cập camera</Text>
        <TouchableOpacity style={styles.permBtn} onPress={requestPermission}>
          <Text style={styles.permBtnText}>Cấp quyền Camera</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const handleScan = async ({ data }: { data: string }) => {
    if (scanned) return;
    setScanned(true);

    try {
      // Parse URI chuẩn TOTP: otpauth://totp/label?secret=XXX&issuer=YYY
      const totp = OTPAuth.URI.parse(data);

      // Lưu vào SecureStore
      const stored = await SecureStore.getItemAsync('accounts');
      const accounts = stored ? JSON.parse(stored) : [];

      accounts.push({
        id: Date.now().toString(),
        label: totp.label,
        issuer: (totp as any).issuer || totp.label,
        secret: totp.secret.base32,
      });

      await SecureStore.setItemAsync('accounts', JSON.stringify(accounts));

      Alert.alert(
        '✅ Thành công!',
        `Đã thêm: ${(totp as any).issuer || totp.label}`,
        [{ text: 'OK', onPress: () => navigation.goBack() }]
      );
    } catch (e) {
      Alert.alert('❌ Lỗi', 'QR code không đúng định dạng TOTP!', [
        { text: 'Thử lại', onPress: () => setScanned(false) }
      ]);
    }
  };

  return (
    <View style={styles.container}>
      <CameraView
        style={StyleSheet.absoluteFillObject}
        onBarcodeScanned={handleScan}
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
      />
      {/* Overlay khung quét */}
      <View style={styles.overlay}>
        <View style={styles.topOverlay} />
        <View style={styles.middleRow}>
          <View style={styles.sideOverlay} />
          <View style={styles.scanBox}>
            {/* 4 góc khung */}
            <View style={[styles.corner, styles.topLeft]} />
            <View style={[styles.corner, styles.topRight]} />
            <View style={[styles.corner, styles.bottomLeft]} />
            <View style={[styles.corner, styles.bottomRight]} />
          </View>
          <View style={styles.sideOverlay} />
        </View>
        <View style={styles.bottomOverlay}>
          <Text style={styles.hint}>Đưa QR code vào khung để quét</Text>
        </View>
      </View>
    </View>
  );
}

const SCAN_SIZE = 260;

const styles = StyleSheet.create({
  container: { flex: 1 },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 20 },
  permText: { fontSize: 16, color: '#333', marginBottom: 20, textAlign: 'center' },
  permBtn: {
    backgroundColor: '#4285F4', paddingHorizontal: 24,
    paddingVertical: 12, borderRadius: 8,
  },
  permBtnText: { color: 'white', fontSize: 16, fontWeight: 'bold' },
  overlay: { flex: 1 },
  topOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.6)' },
  middleRow: { flexDirection: 'row', height: SCAN_SIZE },
  sideOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.6)' },
  bottomOverlay: {
    flex: 1, backgroundColor: 'rgba(0,0,0,0.6)',
    alignItems: 'center', paddingTop: 20,
  },
  hint: { color: 'white', fontSize: 15 },
  scanBox: { width: SCAN_SIZE, height: SCAN_SIZE },
  corner: {
    position: 'absolute', width: 20, height: 20,
    borderColor: 'white', borderWidth: 3,
  },
  topLeft: { top: 0, left: 0, borderRightWidth: 0, borderBottomWidth: 0 },
  topRight: { top: 0, right: 0, borderLeftWidth: 0, borderBottomWidth: 0 },
  bottomLeft: { bottom: 0, left: 0, borderRightWidth: 0, borderTopWidth: 0 },
  bottomRight: { bottom: 0, right: 0, borderLeftWidth: 0, borderTopWidth: 0 },
});
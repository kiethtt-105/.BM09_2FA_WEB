import React, { useState } from 'react';
import { View, Text, StyleSheet, Alert, TouchableOpacity, ActivityIndicator } from 'react-native';
import { CameraView, useCameraPermissions, scanFromURLAsync } from 'expo-camera';
import * as ImagePicker from 'expo-image-picker';
import * as ImageManipulator from 'expo-image-manipulator';
import * as SecureStore from 'expo-secure-store';
import * as OTPAuth from 'otpauth';

export default function ScanScreen({ navigation, route }: any) {
  const [scanned, setScanned] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [permission, requestPermission] = useCameraPermissions();

  const handleQRData = async (data: string) => {
    try {
      const parsed = OTPAuth.URI.parse(data);
      const isHOTP = parsed instanceof OTPAuth.HOTP;

      const stored = await SecureStore.getItemAsync('accounts');
      const accounts = stored ? JSON.parse(stored) : [];

      accounts.push({
        id: Date.now().toString(),
        label: parsed.label,
        issuer: (parsed as any).issuer || parsed.label,
        secret: parsed.secret.base32,
        type: isHOTP ? 'hotp' : 'totp',
        counter: isHOTP ? ((parsed as OTPAuth.HOTP).counter ?? 0) : undefined,
      });

      await SecureStore.setItemAsync('accounts', JSON.stringify(accounts));

      Alert.alert(
        '✅ Thành công!',
        `Đã thêm: ${(parsed as any).issuer || parsed.label}\nLoại: ${isHOTP ? 'HOTP' : 'TOTP'}`,
        [{ text: 'OK', onPress: () => navigation.goBack() }]
      );
    } catch (e) {
      Alert.alert('❌ Lỗi', 'QR code không đúng định dạng TOTP/HOTP!', [
        { text: 'Thử lại', onPress: () => setScanned(false) },
      ]);
    }
  };

  const handleScan = async ({ data }: { data: string }) => {
    if (scanned) return;
    setScanned(true);
    await handleQRData(data);
  };

  // Thử scan ảnh với nhiều kích thước khác nhau để tăng tỉ lệ thành công
  const tryScanWithSizes = async (uri: string): Promise<string | null> => {
    // Danh sách các kích thước thử theo thứ tự (Android cần resize về nhỏ hơn)
    const widths = [1024, 800, 600, 400];

    for (const width of widths) {
      try {
        const manipulated = await ImageManipulator.manipulateAsync(
          uri,
          [{ resize: { width } }],
          { compress: 1, format: ImageManipulator.SaveFormat.JPEG }
        );

        const result = await scanFromURLAsync(manipulated.uri, ['qr']);
        if (result && result.length > 0) {
          return result[0].data;
        }
      } catch (_) {
        // Tiếp tục thử kích thước tiếp theo
      }
    }

    // Thử thêm với ảnh xoay 90° (một số ảnh chụp màn hình bị xoay)
    try {
      const rotated = await ImageManipulator.manipulateAsync(
        uri,
        [{ rotate: 90 }, { resize: { width: 800 } }],
        { compress: 1, format: ImageManipulator.SaveFormat.JPEG }
      );
      const result = await scanFromURLAsync(rotated.uri, ['qr']);
      if (result && result.length > 0) {
        return result[0].data;
      }
    } catch (_) {}

    return null;
  };

  const handlePickImage = async () => {
    const { status } = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (status !== 'granted') {
      Alert.alert('Cần quyền', 'Vui lòng cấp quyền truy cập thư viện ảnh.');
      return;
    }

    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ['images'],
      allowsEditing: false,
      quality: 1,
    });

    if (result.canceled) return;

    setIsProcessing(true);

    try {
      const imageUri = result.assets[0].uri;

      // Bước 1: Thử scan trực tiếp trước (nhanh nhất)
      try {
        const direct = await scanFromURLAsync(imageUri, ['qr']);
        if (direct && direct.length > 0) {
          await handleQRData(direct[0].data);
          return;
        }
      } catch (_) {}

      // Bước 2: Thử với các kích thước resize khác nhau
      const qrData = await tryScanWithSizes(imageUri);
      if (qrData) {
        await handleQRData(qrData);
        return;
      }

      // Không tìm thấy QR sau tất cả các lần thử
      Alert.alert(
        '❌ Không tìm thấy QR',
        'Không đọc được QR từ ảnh này.\n\nMẹo: Thử chụp lại QR code rõ hơn, đủ ánh sáng và không bị mờ.',
        [{ text: 'OK' }]
      );
    } catch (e) {
      Alert.alert('❌ Lỗi', 'Có lỗi xảy ra khi xử lý ảnh.');
    } finally {
      setIsProcessing(false);
    }
  };

  if (!permission) return <View style={styles.container} />;

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

  return (
    <View style={styles.container}>
      <CameraView
        style={StyleSheet.absoluteFillObject}
        onBarcodeScanned={handleScan}
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
      />
      <View style={styles.overlay}>
        <View style={styles.topOverlay} />
        <View style={styles.middleRow}>
          <View style={styles.sideOverlay} />
          <View style={styles.scanBox}>
            <View style={[styles.corner, styles.topLeft]} />
            <View style={[styles.corner, styles.topRight]} />
            <View style={[styles.corner, styles.bottomLeft]} />
            <View style={[styles.corner, styles.bottomRight]} />
          </View>
          <View style={styles.sideOverlay} />
        </View>
        <View style={styles.bottomOverlay}>
          <Text style={styles.hint}>Đưa QR code vào khung để quét</Text>
          <TouchableOpacity
            style={[styles.galleryBtn, isProcessing && styles.galleryBtnDisabled]}
            onPress={handlePickImage}
            disabled={isProcessing}
          >
            {isProcessing ? (
              <View style={styles.loadingRow}>
                <ActivityIndicator size="small" color="#4285F4" />
                <Text style={[styles.galleryBtnText, { marginLeft: 8 }]}>Đang xử lý...</Text>
              </View>
            ) : (
              <Text style={styles.galleryBtnText}>🖼️  Chọn ảnh từ thư viện</Text>
            )}
          </TouchableOpacity>
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
  permBtn: { backgroundColor: '#4285F4', paddingHorizontal: 24, paddingVertical: 12, borderRadius: 8 },
  permBtnText: { color: 'white', fontSize: 16, fontWeight: 'bold' },
  overlay: { flex: 1 },
  topOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.6)' },
  middleRow: { flexDirection: 'row', height: SCAN_SIZE },
  sideOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.6)' },
  bottomOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.6)', alignItems: 'center', paddingTop: 20, gap: 16 },
  hint: { color: 'white', fontSize: 15 },
  galleryBtn: { backgroundColor: 'white', paddingHorizontal: 24, paddingVertical: 12, borderRadius: 10 },
  galleryBtnDisabled: { opacity: 0.6 },
  galleryBtnText: { color: '#333', fontSize: 15, fontWeight: '600' },
  loadingRow: { flexDirection: 'row', alignItems: 'center' },
  scanBox: { width: SCAN_SIZE, height: SCAN_SIZE },
  corner: { position: 'absolute', width: 20, height: 20, borderColor: 'white', borderWidth: 3 },
  topLeft: { top: 0, left: 0, borderRightWidth: 0, borderBottomWidth: 0 },
  topRight: { top: 0, right: 0, borderLeftWidth: 0, borderBottomWidth: 0 },
  bottomLeft: { bottom: 0, left: 0, borderRightWidth: 0, borderTopWidth: 0 },
  bottomRight: { bottom: 0, right: 0, borderLeftWidth: 0, borderTopWidth: 0 },
});
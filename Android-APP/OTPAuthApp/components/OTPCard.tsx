import React, { useState, useEffect } from 'react';
import {
  View, Text, StyleSheet,
  TouchableOpacity, Clipboard, Alert
} from 'react-native';
import * as OTPAuth from 'otpauth';

interface Props {
  account: any;
  onDelete: () => void;
}

export default function OTPCard({ account, onDelete }: Props) {
  const [otp, setOtp] = useState('');
  const [timeLeft, setTimeLeft] = useState(30);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const update = () => {
      try {
        // Sinh mã TOTP chuẩn RFC 6238
        const totp = new OTPAuth.TOTP({
          secret: OTPAuth.Secret.fromBase32(account.secret),
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
        });
        setOtp(totp.generate());
        setTimeLeft(30 - (Math.floor(Date.now() / 1000) % 30));
      } catch (e) {
        setOtp('ERROR');
      }
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  const copyOTP = () => {
    Clipboard.setString(otp);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Màu đếm ngược: đỏ khi sắp hết
  const timerColor = timeLeft <= 5 ? '#e53935' : timeLeft <= 10 ? '#fb8c00' : '#43a047';

  return (
    <View style={styles.card}>
      <View style={styles.leftSection}>
        {/* Icon chữ cái đầu */}
        <View style={styles.avatar}>
          <Text style={styles.avatarText}>
            {(account.issuer || account.label || '?')[0].toUpperCase()}
          </Text>
        </View>
        <View>
          <Text style={styles.issuer}>{account.issuer || 'Unknown'}</Text>
          <Text style={styles.label}>{account.label}</Text>
        </View>
      </View>

      <View style={styles.rightSection}>
        {/* Mã OTP */}
        <TouchableOpacity onPress={copyOTP}>
          <Text style={styles.otp}>
            {otp.slice(0, 3)} {otp.slice(3)}
          </Text>
          <Text style={styles.copyHint}>{copied ? '✅ Đã copy!' : 'Nhấn để copy'}</Text>
        </TouchableOpacity>

        {/* Đếm ngược */}
        <Text style={[styles.timer, { color: timerColor }]}>{timeLeft}s</Text>
      </View>

      {/* Nút xóa */}
      <TouchableOpacity style={styles.deleteBtn} onPress={onDelete}>
        <Text style={styles.deleteText}>🗑</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: 'white', marginHorizontal: 12, marginVertical: 6,
    padding: 16, borderRadius: 16, flexDirection: 'row',
    alignItems: 'center', elevation: 3,
  },
  leftSection: { flexDirection: 'row', alignItems: 'center', flex: 1 },
  avatar: {
    width: 44, height: 44, borderRadius: 22,
    backgroundColor: '#4285F4', justifyContent: 'center',
    alignItems: 'center', marginRight: 12,
  },
  avatarText: { color: 'white', fontSize: 20, fontWeight: 'bold' },
  issuer: { fontSize: 15, fontWeight: 'bold', color: '#222' },
  label: { fontSize: 12, color: '#888', marginTop: 2 },
  rightSection: { alignItems: 'flex-end', marginRight: 8 },
  otp: { fontSize: 26, fontWeight: 'bold', color: '#4285F4', letterSpacing: 3 },
  copyHint: { fontSize: 11, color: '#aaa', textAlign: 'right', marginTop: 2 },
  timer: { fontSize: 13, fontWeight: 'bold', marginTop: 4 },
  deleteBtn: { padding: 6 },
  deleteText: { fontSize: 20 },
});
import React, { useState, useEffect } from 'react';
import {
  View, Text, StyleSheet,
  TouchableOpacity, Alert
} from 'react-native';
import * as Clipboard from 'expo-clipboard';   // dùng expo-clipboard
import * as OTPAuth from 'otpauth';
import * as SecureStore from 'expo-secure-store';

interface Account {
  id: string;
  label: string;
  issuer: string;
  secret: string;
  type: 'totp' | 'hotp';
  counter?: number;
}

interface Props {
  account: Account;
  onDelete: () => void;
  onUpdate: (updated: Account) => void;  // callback khi counter thay đổi
}

export default function OTPCard({ account, onDelete, onUpdate }: Props) {
  const [otp, setOtp] = useState('');
  const [timeLeft, setTimeLeft] = useState(30);
  const [copied, setCopied] = useState(false);

  // --- TOTP: tự cập nhật mỗi giây ---
  useEffect(() => {
    if (account.type === 'hotp') {
      // HOTP: sinh mã từ counter hiện tại (chỉ để hiển thị ban đầu)
      generateHOTP(account.counter ?? 0);
      return;
    }

    const update = () => {
      try {
        const totp = new OTPAuth.TOTP({
          secret: OTPAuth.Secret.fromBase32(account.secret),
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
        });
        setOtp(totp.generate());
        setTimeLeft(30 - (Math.floor(Date.now() / 1000) % 30));
      } catch {
        setOtp('ERROR');
      }
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [account.type, account.counter]);

  const generateHOTP = (counter: number) => {
    try {
      const hotp = new OTPAuth.HOTP({
        secret: OTPAuth.Secret.fromBase32(account.secret),
        algorithm: 'SHA1',
        digits: 6,
        counter,
      });
      setOtp(hotp.generate());
    } catch {
      setOtp('ERROR');
    }
  };

  // Bấm "Lấy mã mới" cho HOTP — tăng counter và lưu lại
  const nextHOTP = async () => {
    const newCounter = (account.counter ?? 0) + 1;
    const updated = { ...account, counter: newCounter };

    // Cập nhật trong SecureStore
    const stored = await SecureStore.getItemAsync('accounts');
    const accounts: Account[] = stored ? JSON.parse(stored) : [];
    const idx = accounts.findIndex(a => a.id === account.id);
    if (idx !== -1) {
      accounts[idx] = updated;
      await SecureStore.setItemAsync('accounts', JSON.stringify(accounts));
    }

    onUpdate(updated);
    generateHOTP(newCounter);
  };

  const copyOTP = async () => {
    await Clipboard.setStringAsync(otp);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const timerColor = timeLeft <= 5 ? '#e53935' : timeLeft <= 10 ? '#fb8c00' : '#43a047';
  const isHOTP = account.type === 'hotp';

  return (
    <View style={styles.card}>
      <View style={styles.leftSection}>
        <View style={[styles.avatar, isHOTP && styles.avatarHOTP]}>
          <Text style={styles.avatarText}>
            {(account.issuer || account.label || '?')[0].toUpperCase()}
          </Text>
        </View>
        <View>
          <Text style={styles.issuer}>{account.issuer || 'Unknown'}</Text>
          <Text style={styles.label}>{account.label}</Text>
          {/* Badge loại */}
          <View style={[styles.badge, isHOTP && styles.badgeHOTP]}>
            <Text style={styles.badgeText}>{isHOTP ? 'HOTP' : 'TOTP'}</Text>
          </View>
        </View>
      </View>

      <View style={styles.rightSection}>
        <TouchableOpacity onPress={copyOTP}>
          <Text style={styles.otp}>
            {otp.slice(0, 3)} {otp.slice(3)}
          </Text>
          <Text style={styles.copyHint}>{copied ? '✅ Đã copy!' : 'Nhấn để copy'}</Text>
        </TouchableOpacity>

        {isHOTP ? (
          // HOTP: nút lấy mã tiếp theo
          <TouchableOpacity style={styles.nextBtn} onPress={nextHOTP}>
            <Text style={styles.nextBtnText}>▶ Mã tiếp</Text>
          </TouchableOpacity>
        ) : (
          // TOTP: đếm ngược
          <Text style={[styles.timer, { color: timerColor }]}>{timeLeft}s</Text>
        )}
      </View>

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
  avatarHOTP: { backgroundColor: '#7B1FA2' },  // màu tím cho HOTP
  avatarText: { color: 'white', fontSize: 20, fontWeight: 'bold' },
  issuer: { fontSize: 15, fontWeight: 'bold', color: '#222' },
  label: { fontSize: 12, color: '#888', marginTop: 2 },
  badge: {
    marginTop: 4, backgroundColor: '#E3F2FD',
    borderRadius: 4, paddingHorizontal: 6, paddingVertical: 1,
    alignSelf: 'flex-start',
  },
  badgeHOTP: { backgroundColor: '#F3E5F5' },
  badgeText: { fontSize: 10, color: '#555', fontWeight: 'bold' },
  rightSection: { alignItems: 'flex-end', marginRight: 8 },
  otp: { fontSize: 26, fontWeight: 'bold', color: '#4285F4', letterSpacing: 3 },
  copyHint: { fontSize: 11, color: '#aaa', textAlign: 'right', marginTop: 2 },
  timer: { fontSize: 13, fontWeight: 'bold', marginTop: 4 },
  nextBtn: {
    marginTop: 6, backgroundColor: '#7B1FA2',
    borderRadius: 6, paddingHorizontal: 10, paddingVertical: 4,
  },
  nextBtnText: { color: 'white', fontSize: 12, fontWeight: 'bold' },
  deleteBtn: { padding: 6 },
  deleteText: { fontSize: 20 },
});
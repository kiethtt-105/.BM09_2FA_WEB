import React, { useState, useEffect } from 'react';
import {
  View, Text, StyleSheet,
  TouchableOpacity, Alert, TextInput, Modal
} from 'react-native';
import * as Clipboard from 'expo-clipboard';
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
  onUpdate: (updated: Account) => void;
}

export default function OTPCard({ account, onDelete, onUpdate }: Props) {
  const [otp, setOtp] = useState('');
  const [timeLeft, setTimeLeft] = useState(30);
  const [copied, setCopied] = useState(false);

  // Modal set counter thủ công
  const [showSetCounter, setShowSetCounter] = useState(false);
  const [inputCounter, setInputCounter] = useState('');

  useEffect(() => {
    if (account.type === 'hotp') {
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
    const code = hotp.generate();
    console.log(`HOTP counter=${counter} → mã=${code}`);  // ← thêm dòng này
    setOtp(code);
  } catch {
    setOtp('ERROR');
  }
};

  // Lưu counter mới vào SecureStore và cập nhật state
  const saveCounter = async (newCounter: number) => {
    const updated = { ...account, counter: newCounter };
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

  // Nút "Mã tiếp" — tăng counter lên 1
  const nextHOTP = async () => {
    const newCounter = (account.counter ?? 0) + 1;
    await saveCounter(newCounter);
  };

  // Nút "Set counter" — user nhập số tùy ý
  const confirmSetCounter = async () => {
    const val = parseInt(inputCounter, 10);
    if (isNaN(val) || val < 0) {
      Alert.alert('Lỗi', 'Vui lòng nhập số nguyên dương hợp lệ.');
      return;
    }
    setShowSetCounter(false);
    setInputCounter('');
    await saveCounter(val);
    Alert.alert('Đã cập nhật', `Counter đã set về ${val}.\nMã hiện tại là mã của counter ${val}.`);
  };

  const copyOTP = async () => {
    await Clipboard.setStringAsync(otp);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const timerColor = timeLeft <= 5 ? '#e53935' : timeLeft <= 10 ? '#fb8c00' : '#43a047';
  const isHOTP = account.type === 'hotp';
  const currentCounter = account.counter ?? 0;

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
          <View style={[styles.badge, isHOTP && styles.badgeHOTP]}>
            <Text style={styles.badgeText}>{isHOTP ? 'HOTP' : 'TOTP'}</Text>
          </View>

          {/* Hiển thị counter hiện tại của app */}
          {isHOTP && (
            <Text style={styles.counterText}>
              Counter app: <Text style={styles.counterNum}>{currentCounter}</Text>
            </Text>
          )}
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
          <View style={styles.hotpBtns}>
            {/* Nút tăng counter lên 1 */}
            <TouchableOpacity style={styles.nextBtn} onPress={nextHOTP}>
              <Text style={styles.nextBtnText}>▶ Tiếp</Text>
            </TouchableOpacity>

            {/* Nút set counter về số bất kỳ */}
            <TouchableOpacity
              style={styles.setBtn}
              onPress={() => {
                setInputCounter(String(currentCounter));
                setShowSetCounter(true);
              }}
            >
              <Text style={styles.setBtnText}>✏️ Set</Text>
            </TouchableOpacity>
          </View>
        ) : (
          <Text style={[styles.timer, { color: timerColor }]}>{timeLeft}s</Text>
        )}
      </View>

      <TouchableOpacity style={styles.deleteBtn} onPress={onDelete}>
        <Text style={styles.deleteText}>🗑</Text>
      </TouchableOpacity>

      {/* Modal nhập counter thủ công */}
      <Modal
        visible={showSetCounter}
        transparent
        animationType="fade"
        onRequestClose={() => setShowSetCounter(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalBox}>
            <Text style={styles.modalTitle}>Set counter cho app</Text>
            <Text style={styles.modalDesc}>
              Nhập đúng số counter đang hiển thị trên web để đồng bộ lại.
            </Text>
            <Text style={styles.modalCurrent}>
              Counter hiện tại của app: <Text style={{ fontWeight: 'bold' }}>{currentCounter}</Text>
            </Text>
            <TextInput
              style={styles.modalInput}
              keyboardType="numeric"
              value={inputCounter}
              onChangeText={setInputCounter}
              placeholder="Nhập số counter..."
              autoFocus
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnCancel]}
                onPress={() => { setShowSetCounter(false); setInputCounter(''); }}
              >
                <Text style={styles.modalBtnTextCancel}>Hủy</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.modalBtn, styles.modalBtnConfirm]}
                onPress={confirmSetCounter}
              >
                <Text style={styles.modalBtnTextConfirm}>Xác nhận</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
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
  avatarHOTP: { backgroundColor: '#7B1FA2' },
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

  // Counter hiển thị dưới badge
  counterText: { fontSize: 11, color: '#999', marginTop: 4 },
  counterNum: { color: '#7B1FA2', fontWeight: 'bold' },

  rightSection: { alignItems: 'flex-end', marginRight: 8 },
  otp: { fontSize: 26, fontWeight: 'bold', color: '#4285F4', letterSpacing: 3 },
  copyHint: { fontSize: 11, color: '#aaa', textAlign: 'right', marginTop: 2 },
  timer: { fontSize: 13, fontWeight: 'bold', marginTop: 4 },

  hotpBtns: { flexDirection: 'row', gap: 6, marginTop: 6 },
  nextBtn: {
    backgroundColor: '#7B1FA2',
    borderRadius: 6, paddingHorizontal: 10, paddingVertical: 4,
  },
  nextBtnText: { color: 'white', fontSize: 12, fontWeight: 'bold' },
  setBtn: {
    backgroundColor: '#E8F5E9',
    borderRadius: 6, paddingHorizontal: 10, paddingVertical: 4,
    borderWidth: 1, borderColor: '#A5D6A7',
  },
  setBtnText: { color: '#2E7D32', fontSize: 12, fontWeight: 'bold' },

  deleteBtn: { padding: 6 },
  deleteText: { fontSize: 20 },

  // Modal
  modalOverlay: {
    flex: 1, backgroundColor: 'rgba(0,0,0,0.45)',
    justifyContent: 'center', alignItems: 'center',
  },
  modalBox: {
    backgroundColor: 'white', borderRadius: 16,
    padding: 24, width: '85%', elevation: 10,
  },
  modalTitle: { fontSize: 17, fontWeight: 'bold', color: '#222', marginBottom: 8 },
  modalDesc: { fontSize: 13, color: '#666', lineHeight: 20, marginBottom: 8 },
  modalCurrent: { fontSize: 13, color: '#444', marginBottom: 14 },
  modalInput: {
    borderWidth: 1, borderColor: '#ccc', borderRadius: 8,
    padding: 10, fontSize: 18, textAlign: 'center',
    letterSpacing: 2, marginBottom: 16,
  },
  modalBtns: { flexDirection: 'row', gap: 10 },
  modalBtn: { flex: 1, borderRadius: 8, padding: 12, alignItems: 'center' },
  modalBtnCancel: { backgroundColor: '#f5f5f5', borderWidth: 1, borderColor: '#ddd' },
  modalBtnConfirm: { backgroundColor: '#7B1FA2' },
  modalBtnTextCancel: { color: '#555', fontWeight: 'bold' },
  modalBtnTextConfirm: { color: 'white', fontWeight: 'bold' },
});
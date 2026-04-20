import React, { useState, useCallback } from 'react';
import {
  View, Text, FlatList,
  StyleSheet, TouchableOpacity, Alert
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { useFocusEffect } from '@react-navigation/native';
import OTPCard from '../components/OTPCard';

export default function HomeScreen({ navigation }: any) {
  const [accounts, setAccounts] = useState<any[]>([]);

  // Load lại danh sách mỗi khi vào màn hình này
  useFocusEffect(
    useCallback(() => {
      loadAccounts();
    }, [])
  );

  const loadAccounts = async () => {
    const data = await SecureStore.getItemAsync('accounts');
    if (data) setAccounts(JSON.parse(data));
    else setAccounts([]);
  };

  const deleteAccount = (id: string) => {
    Alert.alert('Xóa tài khoản', 'Bạn có chắc muốn xóa?', [
      { text: 'Hủy', style: 'cancel' },
      {
        text: 'Xóa', style: 'destructive',
        onPress: async () => {
          const data = await SecureStore.getItemAsync('accounts');
          const accounts = data ? JSON.parse(data) : [];
          const updated = accounts.filter((a: any) => a.id !== id);
          await SecureStore.setItemAsync('accounts', JSON.stringify(updated));
          setAccounts(updated);
        }
      }
    ]);
  };

  return (
    <View style={styles.container}>
      {accounts.length === 0 ? (
        <View style={styles.emptyContainer}>
          <Text style={styles.emptyIcon}>🔐</Text>
          <Text style={styles.emptyText}>Chưa có tài khoản nào</Text>
          <Text style={styles.emptySubText}>Nhấn + để thêm tài khoản</Text>
        </View>
      ) : (
        <FlatList
          data={accounts}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => (
            <OTPCard account={item} onDelete={() => deleteAccount(item.id)} />
          )}
        />
      )}

      {/* Nút thêm tài khoản */}
      <TouchableOpacity
        style={styles.fab}
        onPress={() => navigation.navigate('Scan', { onAdd: loadAccounts })}
      >
        <Text style={styles.fabText}>+</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f0f0' },
  emptyContainer: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  emptyIcon: { fontSize: 60, marginBottom: 16 },
  emptyText: { fontSize: 18, fontWeight: 'bold', color: '#333' },
  emptySubText: { fontSize: 14, color: '#888', marginTop: 8 },
  fab: {
    position: 'absolute', bottom: 30, right: 30,
    backgroundColor: '#4285F4', width: 60, height: 60,
    borderRadius: 30, justifyContent: 'center', alignItems: 'center',
    elevation: 5,
  },
  fabText: { color: 'white', fontSize: 36, lineHeight: 40 },
});
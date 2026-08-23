import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, App as AntApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { AuthProvider } from './app/AuthContext';
import './styles.css';

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 10_000, refetchOnWindowFocus: true } } });

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff', borderRadius: 6, fontSize: 14 }, components: { Layout: { siderBg: '#18212f', headerBg: '#ffffff' }, Menu: { darkItemBg: '#18212f', darkItemSelectedBg: '#1677ff' }, Table: { cellPaddingBlock: 10, cellPaddingInline: 12 } } }}>
      <AntApp><QueryClientProvider client={queryClient}><BrowserRouter><AuthProvider><App /></AuthProvider></BrowserRouter></QueryClientProvider></AntApp>
    </ConfigProvider>
  </React.StrictMode>,
);

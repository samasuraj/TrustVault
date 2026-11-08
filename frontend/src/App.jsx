import React, { useState, useEffect } from 'react';
import { authApi } from './api';
import Navbar from './components/Navbar';
import Login from './components/Login';
import DocumentList from './components/DocumentList';
import DocumentDetail from './components/DocumentDetail';
import UploadModal from './components/UploadModal';
import AdminDashboard from './components/AdminDashboard';

export default function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [activeTab, setActiveTab] = useState('documents'); // 'documents', 'admin'
  const [selectedDoc, setSelectedDoc] = useState(null);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    checkCurrentUser();
  }, []);

  async function checkCurrentUser() {
    try {
      const user = await authApi.getMe();
      setCurrentUser(user);
    } catch {
      setCurrentUser(null);
    } finally {
      setCheckingAuth(false);
    }
  }

  async function handleLogout() {
    try {
      await authApi.logout();
    } catch {
      // Ignored
    } finally {
      setCurrentUser(null);
      setSelectedDoc(null);
      setActiveTab('documents');
    }
  }

  function handleLoginSuccess(user) {
    const u = user?.user || user;
    setCurrentUser(u);
    setSelectedDoc(null);
    setActiveTab(u?.role === 'admin' ? 'admin' : 'documents');
  }

  function handleOpenUpload() {
    setShowUploadModal(true);
  }

  function handleUploadSuccess() {
    setRefreshTrigger((prev) => prev + 1);
  }

  if (checkingAuth) {
    return (
      <div className="app-loader">
        <div className="spinner"></div>
        <p>Loading TrustVault Secure Environment...</p>
      </div>
    );
  }

  if (!currentUser) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="app-root">
      <Navbar
        user={currentUser}
        activeTab={activeTab}
        onTabChange={(tab) => {
          setActiveTab(tab);
          setSelectedDoc(null);
        }}
        onOpenUpload={handleOpenUpload}
        onLogout={handleLogout}
      />

      <main className="main-container">
        {activeTab === 'documents' && (
          selectedDoc ? (
            <DocumentDetail
              key={selectedDoc.id}
              docId={selectedDoc.id}
              currentUser={currentUser}
              onBack={() => {
                setSelectedDoc(null);
                setRefreshTrigger((prev) => prev + 1);
              }}
            />
          ) : (
            <DocumentList
              key={refreshTrigger}
              currentUser={currentUser}
              onSelectDoc={(d) => setSelectedDoc(d)}
              onOpenUpload={handleOpenUpload}
            />
          )
        )}

        {activeTab === 'admin' && (
          <AdminDashboard currentUser={currentUser} />
        )}
      </main>

      {showUploadModal && (
        <UploadModal
          onClose={() => setShowUploadModal(false)}
          onUploadSuccess={handleUploadSuccess}
        />
      )}
    </div>
  );
}

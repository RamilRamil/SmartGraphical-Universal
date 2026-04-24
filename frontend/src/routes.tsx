import { Navigate, Route, Routes } from "react-router-dom";

import { ArtifactDetailPage } from "./pages/ArtifactDetailPage";
import { DiffPage } from "./pages/DiffPage";
import { HistoryPage } from "./pages/HistoryPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { UploadPage } from "./pages/UploadPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/upload" replace />} />
      <Route path="/upload" element={<UploadPage />} />
      <Route path="/history" element={<HistoryPage />} />
      <Route path="/artifacts/:artifactId" element={<ArtifactDetailPage />} />
      <Route path="/scans/:scanA/diff/:scanB" element={<DiffPage />} />
      <Route path="/scans/:scanId" element={<ScanDetailPage />} />
      <Route path="*" element={<Navigate to="/upload" replace />} />
    </Routes>
  );
}

import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Layout } from './layouts/Layout';
import { Overview } from './pages/Overview';
import { Decisions } from './pages/Decisions';
import { CrossService } from './pages/CrossService';
import { Evaluation } from './pages/Evaluation';
import { Benchmarks } from './pages/Benchmarks';
import { Approvals } from './pages/Approvals';
import { IncomingEmails } from './pages/IncomingEmails';
import { AuditTrail } from './pages/AuditTrail';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="decisions" element={<Decisions />} />
          <Route path="security/cross-service" element={<CrossService />} />
          <Route path="evaluation" element={<Evaluation />} />
          <Route path="benchmarks" element={<Benchmarks />} />
          <Route path="approvals" element={<Approvals />} />
          <Route path="emails" element={<IncomingEmails />} />
          <Route path="audit" element={<AuditTrail />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;

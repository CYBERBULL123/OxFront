'use client'

import React from 'react';
import Layout from '../../components/Layout';
import { motion } from 'framer-motion';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ScatterChart,
  Scatter,
} from 'recharts';
import { MapContainer, TileLayer, Marker, Popup, Polyline, Tooltip as LeafletTooltip } from 'react-leaflet';
import { Shield, AlertTriangle, CheckCircle, Activity } from 'lucide-react';
import 'leaflet/dist/leaflet.css';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];
const threatData = [
  { name: 'Jan', Threats: 4000, Mitigations: 2400 },
  { name: 'Feb', Threats: 3000, Mitigations: 1398 },
  { name: 'Mar', Threats: 2000, Mitigations: 9800 },
  { name: 'Apr', Threats: 2780, Mitigations: 3908 },
  { name: 'May', Threats: 1890, Mitigations: 4800 },
  { name: 'Jun', Threats: 2390, Mitigations: 3800 },
];

const pieData = [
  { name: 'Malware', value: 400 },
  { name: 'Phishing', value: 300 },
  { name: 'DDoS', value: 300 },
  { name: 'Other', value: 200 },
];

const radarData = [
  { category: 'Network', score: 120 },
  { category: 'Application', score: 98 },
  { category: 'Database', score: 86 },
  { category: 'Endpoint', score: 99 },
  { category: 'Cloud', score: 85 },
];

const attackLocations = [
  { lat: 51.505, lng: -0.09, name: 'London', country: 'UK', region: 'Europe', details: 'Financial systems compromised' },
  { lat: 40.7128, lng: -74.0060, name: 'New York', country: 'USA', region: 'North America', details: 'DDoS attack on government servers' },
  { lat: 34.0522, lng: -118.2437, name: 'Los Angeles', country: 'USA', region: 'North America', details: 'Data breach in media companies' },
  { lat: 48.8566, lng: 2.3522, name: 'Paris', country: 'France', region: 'Europe', details: 'Ransomware targeting hospitals' },
  { lat: 35.6895, lng: 139.6917, name: 'Tokyo', country: 'Japan', region: 'Asia', details: 'Phishing attack on corporations' },
  { lat: 55.7558, lng: 37.6173, name: 'Moscow', country: 'Russia', region: 'Europe', details: 'Advanced persistent threat (APT)' },
  { lat: -33.8688, lng: 151.2093, name: 'Sydney', country: 'Australia', region: 'Oceania', details: 'Supply chain attack' },
  { lat: 19.0760, lng: 72.8777, name: 'Mumbai', country: 'India', region: 'Asia', details: 'Critical infrastructure targeted' },
  { lat: -23.5505, lng: -46.6333, name: 'São Paulo', country: 'Brazil', region: 'South America', details: 'Social engineering attacks' },
  { lat: 39.9042, lng: 116.4074, name: 'Beijing', country: 'China', region: 'Asia', details: 'Espionage campaigns' },
  { lat: 41.9028, lng: 12.4964, name: 'Rome', country: 'Italy', region: 'Europe', details: 'Banking fraud attacks' },
  { lat: -26.2041, lng: 28.0473, name: 'Johannesburg', country: 'South Africa', region: 'Africa', details: 'Ransomware on healthcare systems' },
  { lat: 1.3521, lng: 103.8198, name: 'Singapore', country: 'Singapore', region: 'Asia', details: 'Critical database breach' },
  { lat: 37.7749, lng: -122.4194, name: 'San Francisco', country: 'USA', region: 'North America', details: 'Tech firm cyberattack' },
  { lat: 52.5200, lng: 13.4050, name: 'Berlin', country: 'Germany', region: 'Europe', details: 'Malware in energy systems' },
  { lat: 35.6895, lng: 51.3890, name: 'Tehran', country: 'Iran', region: 'Asia', details: 'Military data breach' },
  { lat: 31.2304, lng: 121.4737, name: 'Shanghai', country: 'China', region: 'Asia', details: 'Intellectual property theft' },
  { lat: -34.6037, lng: -58.3816, name: 'Buenos Aires', country: 'Argentina', region: 'South America', details: 'Government systems hacked' },
  { lat: 6.5244, lng: 3.3792, name: 'Lagos', country: 'Nigeria', region: 'Africa', details: 'Business email compromise' },
  { lat: 45.5017, lng: -73.5673, name: 'Montreal', country: 'Canada', region: 'North America', details: 'Ransomware on education sector' },
  { lat: 28.6139, lng: 77.2090, name: 'New Delhi', country: 'India', region: 'Asia', details: 'Cyber espionage on ministries' },
  { lat: 22.3964, lng: 114.1095, name: 'Hong Kong', country: 'Hong Kong', region: 'Asia', details: 'Distributed denial-of-service (DDoS)' },
  { lat: 40.4168, lng: -3.7038, name: 'Madrid', country: 'Spain', region: 'Europe', details: 'Online scam campaigns' },
  { lat: -37.8136, lng: 144.9631, name: 'Melbourne', country: 'Australia', region: 'Oceania', details: 'Data leak in healthcare' },
];

// Custom Icon
const attackIcon = new L.Icon({
  iconUrl: 'https://i.ibb.co/vdBy68m/hacker.png', // Replace with your custom icon URL
  iconSize: [32, 32],
  iconAnchor: [16, 32],
  popupAnchor: [0, -32],
});

export default function Dashboard() {
  const polylinePositions = attackLocations.map((loc) => [loc.lat, loc.lng]);

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h2 className="text-3xl font-semibold text-gray-800 dark:text-white mb-6">
          Cybersecurity Dashboard
        </h2>

        <div className="grid gap-6 mb-8 md:grid-cols-2 xl:grid-cols-4">
          <div className="flex items-center p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <div className="p-3 mr-4 text-orange-500 bg-orange-100 rounded-full dark:text-orange-100 dark:bg-orange-500">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">Total Threats</p>
              <p className="text-lg font-semibold text-gray-700 dark:text-gray-200">6,389</p>
            </div>
          </div>
          <div className="flex items-center p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <div className="p-3 mr-4 text-green-500 bg-green-100 rounded-full dark:text-green-100 dark:bg-green-500">
              <CheckCircle className="w-5 h-5" />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">Mitigations</p>
              <p className="text-lg font-semibold text-gray-700 dark:text-gray-200">5,280</p>
            </div>
          </div>
          <div className="flex items-center p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <div className="p-3 mr-4 text-blue-500 bg-blue-100 rounded-full dark:text-blue-100 dark:bg-blue-500">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">Active Alerts</p>
              <p className="text-lg font-semibold text-gray-700 dark:text-gray-200">376</p>
            </div>
          </div>
          <div className="flex items-center p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <div className="p-3 mr-4 text-teal-500 bg-teal-100 rounded-full dark:text-teal-100 dark:bg-teal-500">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">System Health</p>
              <p className="text-lg font-semibold text-gray-700 dark:text-gray-200">98%</p>
            </div>
          </div>
        </div>

        <div className="grid gap-6 mb-8 md:grid-cols-2 xl:grid-cols-3">
          <div className="p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <h4 className="mb-4 font-semibold text-gray-800 dark:text-gray-300">Threats vs Mitigations</h4>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={threatData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="Threats" fill="#8884d8" />
                <Bar dataKey="Mitigations" fill="#82ca9d" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <h4 className="mb-4 font-semibold text-gray-800 dark:text-gray-300">Threat Types</h4>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800">
            <h4 className="mb-4 font-semibold text-gray-800 dark:text-gray-300">Security Coverage</h4>
            <ResponsiveContainer width="100%" height={300}>
              <RadarChart data={radarData} outerRadius={90}>
                <PolarGrid />
                <PolarAngleAxis dataKey="category" />
                <PolarRadiusAxis />
                <Radar name="Security" dataKey="score" stroke="#8884d8" fill="#8884d8" fillOpacity={0.6} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="w-full h-[400px] rounded-lg bg-white shadow-md dark:bg-gray-800">
          <MapContainer center={[51.505, -0.09]} zoom={2} scrollWheelZoom={true} style={{ width: '100%', height: '100%' }}>
            <TileLayer url="https://tiles.stadiamaps.com/tiles/alidade_smooth_dark/{z}/{x}/{y}{r}.png" />
            {attackLocations.map((loc, index) => (
              <Marker key={index} position={[loc.lat, loc.lng]} icon={attackIcon}>
                <Popup>
                  <strong>{loc.name}</strong><br />
                  {loc.details}<br />
                  <small>{loc.region}, {loc.country}</small>
                </Popup>
              </Marker>
            ))}
            <Polyline positions={polylinePositions} color="blue" />
          </MapContainer>
        </div>
      </motion.div>
    </Layout>
  );
}

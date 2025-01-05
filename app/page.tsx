import React from "react";
import Link from "next/link";
import { ArrowRight, Shield, Zap, Brain, Cpu, Cloud, Users } from "lucide-react";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-black text-white">

      {/* Header with Logo */}
      <header className="fixed top-0 left-0 right-0 z-50 flex justify-center items-center p-6 backdrop-blur-md bg-opacity-30">
        <div className="flex items-center justify-center space-x-4">
          <img
            src="https://i.ibb.co/qjFfNqg/generated-image-3-1.png"
            alt="OxSuite Logo"
            className="h-16 w-16 rounded-full border-4 border-cyan-500"
          />
          <h1 className="text-1xl sm:text-1xl md:text-1xl font-extrabold tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-cyan-500 to-blue-500 text-center">
            OxSuite by OxSecure Intelligence
          </h1>
        </div>
      </header>

      {/* Hero Section with Dynamic Animated Background */}
      <section className="relative flex items-center justify-center h-screen bg-cover bg-center bg-no-repeat overflow-hidden rounded-3xl"
        style={{ animation: 'bgMove 15s infinite linear' }}>
        <div className="absolute inset-0 bg-gradient-to-t from-black via-transparent to-black opacity-80 backdrop-blur-[78px] rounded-3xl"></div>
        <div className="z-10 text-center px-6 md:px-12">
          <h2 className="text-5xl sm:text-6xl md:text-7xl font-extrabold mb-6 text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 to-blue-500">
            Elevate Your Cybersecurity with OxSuite
          </h2>
          <p className="text-lg md:text-xl mb-12 text-gray-300 max-w-4xl mx-auto">
            Revolutionizing threat detection, data protection, and AI-driven security tools to ensure the safety of businesses of tomorrow.
          </p>
          <div className="flex justify-center items-center gap-6">
            <Link href="/login" className="bg-cyan-500 hover:bg-cyan-400 text-white font-bold py-4 px-8 rounded-lg text-lg transition transform hover:scale-105">
              Get Started
            </Link>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-24 bg-gray-900">
        <h2 className="text-4xl font-extrabold text-center text-white mb-12">
          Features & Benefits
        </h2>
        <div className="container mx-auto px-6 grid md:grid-cols-3 gap-12">
          {/* Feature: OxIntell */}
          <div className="bg-gray-800 p-12 rounded-2xl shadow-xl hover:scale-105 transition-all duration-300 ease-in-out relative group">
            <Shield className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-3xl font-bold mb-4 text-white">OxIntell</h3>
            <p className="text-lg text-gray-300 mb-4">AI-driven threat intelligence and real-time alerts to safeguard your data.</p>
          </div>

          {/* Feature: OxImaGen */}
          <div className="bg-gray-800 p-12 rounded-2xl shadow-xl hover:scale-105 transition-all duration-300 ease-in-out relative group">
            <Zap className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-3xl font-bold mb-4 text-white">OxImaGen</h3>
            <p className="text-lg text-gray-300 mb-4">Generate and analyze security images with AI-powered analysis tools.</p>
          </div>

          {/* Feature: OxRAG */}
          <div className="bg-gray-800 p-12 rounded-2xl shadow-xl hover:scale-105 transition-all duration-300 ease-in-out relative group">
            <Brain className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-3xl font-bold mb-4 text-white">OxRAG</h3>
            <p className="text-lg text-gray-300 mb-4">Revolutionary Retrieval-Augmented Generation for precise cybersecurity insights.</p>
          </div>
        </div>
      </section>

      {/* Client Feedback Section */}
      <section className="py-24 bg-gray-900 text-white">
        <h2 className="text-4xl font-extrabold text-center mb-12">What Our Clients Say</h2>
        <div className="container mx-auto px-6 text-center">
          <div className="flex justify-center gap-12">
            <div className="w-full max-w-sm bg-gray-800 p-8 rounded-2xl shadow-xl transform hover:scale-105 transition duration-300 ease-in-out">
              <p className="text-lg mb-4">"OxSuite has transformed our cybersecurity approach. The real-time threat intelligence and AI-driven tools have made our business more secure than ever before."</p>
              <p className="font-bold text-cyan-500">John Doe</p>
              <p className="text-gray-400">CEO, TechCorp</p>
            </div>
            <div className="w-full max-w-sm bg-gray-800 p-8 rounded-2xl shadow-xl transform hover:scale-105 transition duration-300 ease-in-out">
              <p className="text-lg mb-4">"The level of protection and insight that OxSuite provides is unparalleled. Our systems have never been more secure."</p>
              <p className="font-bold text-cyan-500">Jane Smith</p>
              <p className="text-gray-400">CTO, Innovatech</p>
            </div>
          </div>
        </div>
      </section>


      {/* Footer */}
      <footer className="bg-gray-900 py-8 text-center text-gray-400">
        <div className="container mx-auto px-6">
          <p>&copy; 2025 OxSuite. All rights reserved.</p>
          <div className="mt-4">
            <Link href="/terms" className="mx-3 hover:text-white">Terms of Service</Link>
            <Link href="/privacy" className="mx-3 hover:text-white">Privacy Policy</Link>
            <Link href="/contact" className="mx-3 hover:text-white">Contact</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

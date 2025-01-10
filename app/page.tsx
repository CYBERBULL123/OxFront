"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Lock, Globe, Shield, Zap, Brain, Cpu, Cloud, User } from "lucide-react";
import { motion } from "framer-motion";
import { Swiper, SwiperSlide } from "swiper/react";
import "swiper/css";
import "swiper/css/pagination";
import { Pagination, Autoplay } from "swiper/modules";

export default function LandingPage() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setLoading(false), 2000); // Simulate loading
    return () => clearTimeout(timer);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className="w-20 h-20 border-4 border-cyan-500 rounded-full border-t-transparent"
        ></motion.div>
      </div>
    );
  }

  const testimonials = [
    {
      id: 1,
      text: "OxSuite has transformed our cybersecurity approach. The real-time threat intelligence and AI-driven tools have made our business more secure than ever before.",
      name: "Jack Neils",
      role: "CTO, TechCorp",
    },
    {
      id: 2,
      text: "The level of protection and insight that OxSuite provides is unparalleled. Our systems have never been more secure.",
      name: "Jane Smith",
      role: "CTO, Innovatech",
    },
    {
      id: 3,
      text: "OxSuite's AI-driven tools are a game-changer. We've seen a significant reduction in threats since implementing their solutions.",
      name: "Michael Brown",
      role: "CEO, SecureTech",
    },
    {
      id: 4,
      text: "The user-friendly interface and advanced features make OxSuite the best cybersecurity solution we've ever used.",
      name: "Sarah Johnson",
      role: "CTO, DataSafe",
    },
  ];

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
      <section className="relative flex items-center justify-center h-screen bg-cover bg-center bg-no-repeat overflow-hidden rounded-3xl">
        <div className="absolute inset-0 bg-gradient-to-t from-black via-transparent to-black opacity-80 backdrop-blur-[78px] rounded-3xl"></div>
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1 }}
          className="z-10 text-center px-6 md:px-12"
        >
          <h2 className="text-5xl sm:text-6xl md:text-7xl font-extrabold mb-6 text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 to-blue-500">
            Elevate Your Cybersecurity with OxSuite
          </h2>
          <p className="text-lg md:text-xl mb-12 text-gray-300 max-w-4xl mx-auto">
            Revolutionizing threat detection, data protection, and AI-driven security tools to ensure the safety of businesses of tomorrow.
          </p>
          <div className="flex justify-center items-center gap-6">
            <Link
              href="/login"
              className="bg-cyan-500 hover:bg-cyan-400 text-white font-bold py-4 px-8 rounded-lg text-lg transition transform hover:scale-105"
            >
              Get Started
            </Link>
          </div>
        </motion.div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-24 bg-gray-900">
        <h2 className="text-4xl font-extrabold text-center text-white mb-12">
          Features & Benefits
        </h2>
        <div className="container mx-auto px-6 grid md:grid-cols-3 gap-12">
          {/* Feature: OxIntell */}
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="bg-gray-800 p-12 rounded-2xl shadow-xl transition-all duration-300 ease-in-out relative group"
          >
            <Shield className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-3xl font-bold mb-4 text-white">OxIntell</h3>
            <p className="text-lg text-gray-300 mb-4">AI-driven threat intelligence and real-time alerts to safeguard your data.</p>
          </motion.div>

          {/* Feature: OxImaGen */}
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="bg-gray-800 p-12 rounded-2xl shadow-xl transition-all duration-300 ease-in-out relative group"
          >
            <Zap className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-3xl font-bold mb-4 text-white">OxImaGen</h3>
            <p className="text-lg text-gray-300 mb-4">Generate and analyze security images with AI-powered analysis tools.</p>
          </motion.div>

          {/* Feature: OxRAG */}
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="bg-gray-800 p-12 rounded-2xl shadow-xl transition-all duration-300 ease-in-out relative group"
          >
            <Brain className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-3xl font-bold mb-4 text-white">OxRAG</h3>
            <p className="text-lg text-gray-300 mb-4">Revolutionary Retrieval-Augmented Generation for precise cybersecurity insights.</p>
          </motion.div>
        </div>
      </section>

      {/* Why Choose OxSuite Section */}
      <section className="py-24 bg-gray-900">
        <h2 className="text-3xl font-bold mb-12 text-center">Why Choose OxSuite?</h2>
        <div className="container mx-auto px-6 grid md:grid-cols-3 gap-12">
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="bg-gray-800 p-12 rounded-2xl shadow-xl transition-all duration-300 ease-in-out relative group"
          >
            <User className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-xl font-semibold mb-4">User-Friendly Interface</h3>
            <p>Our intuitive design makes complex cybersecurity tasks accessible to all skill levels.</p>
          </motion.div>
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="bg-gray-800 p-12 rounded-2xl shadow-xl transition-all duration-300 ease-in-out relative group"
          >
            <Globe className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-xl font-semibold mb-4">Global Threat Intelligence</h3>
            <p>Stay ahead of cyber threats with our constantly updated global threat database.</p>
          </motion.div>
          <motion.div
            whileHover={{ scale: 1.05 }}
            className="bg-gray-800 p-12 rounded-2xl shadow-xl transition-all duration-300 ease-in-out relative group"
          >
            <Lock className="w-20 h-20 mb-6 text-cyan-500 group-hover:scale-110 transition duration-300 ease-in-out" />
            <h3 className="text-xl font-semibold mb-4">Advanced Encryption</h3>
            <p>Protect your sensitive data with our state-of-the-art encryption technologies.</p>
          </motion.div>
        </div>
      </section>

      {/* Client Feedback Section */}
      <section className="py-24 bg-gray-900 text-white">
        <h2 className="text-4xl font-extrabold text-center mb-12">What Our Clients Say</h2>
        <div className="container mx-auto px-6">
          <Swiper
            pagination={{ clickable: true }}
            autoplay={{ delay: 5000, disableOnInteraction: false }}
            modules={[Pagination, Autoplay]}
            spaceBetween={30}
            slidesPerView={1}
            breakpoints={{
              768: {
                slidesPerView: 2,
              },
            }}
          >
            {testimonials.map((testimonial) => (
              <SwiperSlide key={testimonial.id}>
                <div className="bg-gray-800 p-8 rounded-2xl shadow-xl transform hover:scale-105 transition duration-300 ease-in-out h-full">
                  <p className="text-lg mb-4">{testimonial.text}</p>
                  <User className="w-20 h-20 mb-6 text-cyan-500 mx-auto" />
                  <p className="font-bold text-cyan-500">{testimonial.name}</p>
                  <p className="text-gray-400">{testimonial.role}</p>
                </div>
              </SwiperSlide>
            ))}
          </Swiper>
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
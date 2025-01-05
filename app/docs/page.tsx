'use client'

import React from 'react'
import Layout from '../../components/Layout'
import { motion } from 'framer-motion'
import { Book, FileText, Code, HelpCircle, Brain, Image, Database } from 'lucide-react'
import Link from 'next/link'

export default function Documentation() {
  const sections = [
    { title: 'Getting Started', icon: Book, content: 'Learn how to set up and start using OxSuite.', link: '/docs/started' },
    { title: 'OxIntell', icon: Brain, content: 'Advanced threat intelligence and analysis platform.', link: '/docs/oxintell' },
    { title: 'OxImaGen', icon: Image, content: 'AI-powered image generation and analysis for cybersecurity.', link: '/docs/oximage' },
    { title: 'OxRAG', icon: Database, content: 'Retrieval-Augmented Generation for enhanced insights.', link: '/docs/oxrag' },
    { title: 'API Reference', icon: Code, content: 'Complete API documentation for developers.', link: '/docs/api' },
    { title: 'FAQs', icon: HelpCircle, content: 'Answers to frequently asked questions about OxSuite.', link: '/docs/faq' },
  ]

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h2 className="text-3xl font-semibold text-gray-800 dark:text-white mb-6">Documentation</h2>
        <div className="grid gap-6 mb-8 md:grid-cols-2 lg:grid-cols-3">
          {sections.map((section, index) => (
            <motion.div
              key={section.title}
              className="min-w-0 p-4 bg-white rounded-lg shadow-xs dark:bg-gray-800"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
            >
              <div className="flex items-center mb-4">
                <section.icon className="w-6 h-6 mr-2 text-purple-600" />
                <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">{section.title}</h3>
              </div>
              <p className="text-gray-600 dark:text-gray-400 mb-4">{section.content}</p>
              <Link href={section.link} className="inline-block text-purple-600 hover:text-purple-700 dark:text-purple-400 dark:hover:text-purple-300">
                Read more →
              </Link>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </Layout>
  )
}


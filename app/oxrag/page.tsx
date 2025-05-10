'use client'

import React, { useState, useRef } from 'react'
import Layout from '../../components/Layout'
import { motion } from 'framer-motion'
import { Search, Database, FileText, Link2, Image as ImageIcon, Loader } from 'lucide-react'
import { analyzeText, analyzePdf, analyzeUrl, analyzeImage } from '@/lib/api'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'

const OxRAG: React.FC = () => {
  const [activeTab, setActiveTab] = useState('text')
  const [query, setQuery] = useState('')
  const [text, setText] = useState('')
  const [url, setUrl] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query) {
      alert('Please enter a query')
      return
    }
    
    setLoading(true)
    try {
      let analysisResult: string
      
      switch (activeTab) {
        case 'text':
          if (!text) {
            alert('Please enter some text to analyze')
            setLoading(false)
            return
          }
          analysisResult = await analyzeText(text, query)
          break
        case 'pdf':
          if (!file) {
            alert('Please upload a PDF file')
            setLoading(false)
            return
          }
          analysisResult = await analyzePdf(file, query)
          break
        case 'url':
          if (!url) {
            alert('Please enter a URL')
            setLoading(false)
            return
          }
          analysisResult = await analyzeUrl(url, query)
          break
        case 'image':
          if (!file) {
            alert('Please upload an image')
            setLoading(false)
            return
          }
          analysisResult = await analyzeImage(file, query)
          break
        default:
          analysisResult = 'Invalid analysis type'
      }
      
      setResult(analysisResult)
    } catch (error) {
      console.error('Error analyzing:', error)
      setResult('An error occurred while analyzing the query.')
    }
    setLoading(false)
  }

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6"
      >
        <h1 className="text-3xl font-bold mb-6 text-green-600 dark:text-green-400">OxRAG - Research Assistant</h1>
        <p className="text-gray-600 dark:text-gray-300 mb-8">
          Analyze text, PDFs, URLs, and images with AI-powered research and analysis
        </p>
        
        <form onSubmit={handleSubmit} className="mb-8">
          <div className="relative mb-6">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter your research query..."
              className="w-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg py-3 px-4 pl-12 focus:outline-none focus:border-green-500"
            />
            <Search className="absolute left-4 top-3.5 text-gray-400" size={20} />
          </div>
          
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full mb-6">
            <TabsList className="w-full bg-gray-100 dark:bg-gray-700 p-1 rounded-lg">
              <TabsTrigger value="text" className="flex-1">
                <FileText className="mr-2" size={16} />
                Text
              </TabsTrigger>
              <TabsTrigger value="pdf" className="flex-1">
                <FileText className="mr-2" size={16} />
                PDF
              </TabsTrigger>
              <TabsTrigger value="url" className="flex-1">
                <Link2 className="mr-2" size={16} />
                URL
              </TabsTrigger>
              <TabsTrigger value="image" className="flex-1">
                <ImageIcon className="mr-2" size={16} />
                Image
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="text" className="mt-4">
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Enter or paste text to analyze..."
                className="w-full h-40 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg py-3 px-4 focus:outline-none focus:border-green-500"
              />
            </TabsContent>
            
            <TabsContent value="pdf" className="mt-4">
              <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center">
                <input
                  type="file"
                  accept=".pdf"
                  ref={fileInputRef}
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="hidden"
                />
                <FileText className="mx-auto mb-4 text-gray-400" size={48} />
                <p className="mb-2 text-gray-600 dark:text-gray-300">
                  {file ? file.name : 'Upload a PDF file'}
                </p>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="mt-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 font-medium py-2 px-4 rounded-lg transition-colors duration-200"
                >
                  Choose File
                </button>
              </div>
            </TabsContent>
            
            <TabsContent value="url" className="mt-4">
              <div className="relative">
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="Enter a URL to analyze (e.g., https://example.com)"
                  className="w-full bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg py-3 px-4 pl-12 focus:outline-none focus:border-green-500"
                />
                <Link2 className="absolute left-4 top-3.5 text-gray-400" size={20} />
              </div>
            </TabsContent>
            
            <TabsContent value="image" className="mt-4">
              <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center">
                <input
                  type="file"
                  accept="image/*"
                  ref={fileInputRef}
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="hidden"
                />
                <ImageIcon className="mx-auto mb-4 text-gray-400" size={48} />
                <p className="mb-2 text-gray-600 dark:text-gray-300">
                  {file ? file.name : 'Upload an image'}
                </p>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="mt-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 font-medium py-2 px-4 rounded-lg transition-colors duration-200"
                >
                  Choose Image
                </button>
              </div>
            </TabsContent>
          </Tabs>
          
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-green-500 hover:bg-green-600 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
          >
            {loading ? (
              <>
                <Loader className="animate-spin mr-2" size={20} />
                Analyzing...
              </>
            ) : (
              <>
                <Search className="mr-2" size={20} />
                Analyze with AI
              </>
            )}
          </button>
        </form>
        
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mt-6 bg-gray-100 dark:bg-gray-700 rounded-lg p-6 shadow-inner"
          >
            <h2 className="text-xl font-semibold mb-4 text-gray-800 dark:text-white">Analysis Results</h2>
            <div 
              className="prose prose-green dark:prose-invert max-w-none"
              dangerouslySetInnerHTML={{ 
                __html: result.replace(/\n/g, '<br />').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') 
              }}
            />
          </motion.div>
        )}
        
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-6 border border-blue-100 dark:border-blue-800">
            <h3 className="text-lg font-semibold mb-3 text-blue-700 dark:text-blue-400">About OxRAG</h3>
            <p className="text-gray-600 dark:text-gray-300">
              OxRAG uses advanced AI to analyze various content types, extracting insights and answering complex questions with contextual understanding.
            </p>
          </div>
          
          <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-6 border border-purple-100 dark:border-purple-800">
            <h3 className="text-lg font-semibold mb-3 text-purple-700 dark:text-purple-400">Research Capabilities</h3>
            <p className="text-gray-600 dark:text-gray-300">
              Extract information from text, PDFs, websites, and images. Perfect for academic research, competitive analysis, and data exploration.
            </p>
          </div>
        </div>
      </motion.div>
    </Layout>
  )
}

export default OxRAG


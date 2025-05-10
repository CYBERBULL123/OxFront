'use client'

import React, { useState, useRef } from 'react'
import Layout from '../../components/Layout'
import { motion } from 'framer-motion'
import { Upload, ImageIcon, Zap, Sparkles, Download, Loader } from 'lucide-react'
import { generateImage, enhanceImage } from '@/lib/api'

const OxImaGen: React.FC = () => {
  const [prompt, setPrompt] = useState('')
  const [image, setImage] = useState<File | null>(null)
  const [enhancePrompt, setEnhancePrompt] = useState('')
  const [generatedImageData, setGeneratedImageData] = useState<string | null>(null)
  const [enhancementResult, setEnhancementResult] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [enhanceLoading, setEnhanceLoading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setImage(e.target.files[0])
    }
  }

  const handleGenerateImage = async () => {
    if (!prompt) {
      alert('Please enter a prompt for image generation')
      return
    }
    
    setLoading(true)
    try {
      const imageData = await generateImage(prompt)
      setGeneratedImageData(imageData)
    } catch (error) {
      console.error('Error generating image:', error)
      alert('Error generating image. Please try again.')
    }
    setLoading(false)
  }
  
  const handleEnhanceImage = async () => {
    if (!image) {
      alert('Please upload an image to enhance')
      return
    }
    
    if (!enhancePrompt) {
      alert('Please enter enhancement instructions')
      return
    }
    
    setEnhanceLoading(true)
    try {
      const result = await enhanceImage(image, enhancePrompt)
      setEnhancementResult(result)
    } catch (error) {
      console.error('Error enhancing image:', error)
      alert('Error enhancing image. Please try again.')
    }
    setEnhanceLoading(false)
  }

  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6"
      >
        <h1 className="text-3xl font-bold mb-6 text-purple-600 dark:text-purple-400">OxImaGen - AI Image Studio</h1>
        <p className="text-gray-600 dark:text-gray-300 mb-8">
          Generate stunning images from text prompts or enhance existing images with AI
        </p>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Image Generation Section */}
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="bg-gradient-to-br from-purple-50 to-pink-50 dark:from-purple-900/20 dark:to-pink-900/10 p-6 rounded-lg border border-purple-100 dark:border-purple-800/30"
          >
            <h2 className="text-xl font-semibold mb-4 flex items-center text-purple-700 dark:text-purple-400">
              <Sparkles className="mr-2" size={24} />
              Generate New Image
            </h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Enter a detailed description
                </label>
                <textarea
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="Describe the image you want to generate in detail..."
                  className="w-full h-32 bg-white dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg py-3 px-4 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                />
              </div>
              
              <button
                onClick={handleGenerateImage}
                disabled={!prompt || loading}
                className="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
              >
                {loading ? (
                  <>
                    <Loader className="animate-spin mr-2" size={20} />
                    Generating...
                  </>
                ) : (
                  <>
                    <Sparkles className="mr-2" size={20} />
                    Generate Image
                  </>
                )}
              </button>
            </div>
            
            {generatedImageData && (
              <div className="mt-6">
                <h3 className="text-lg font-medium mb-2 text-purple-700 dark:text-purple-400">Generated Image</h3>
                <div className="border border-purple-200 dark:border-purple-800/50 rounded-lg overflow-hidden">
                  <img 
                    src={`data:image/png;base64,${generatedImageData}`} 
                    alt="AI Generated" 
                    className="w-full h-auto" 
                  />
                </div>
                <a
                  href={`data:image/png;base64,${generatedImageData}`}
                  download="oximage-generated.png"
                  className="mt-2 text-purple-600 dark:text-purple-400 flex items-center hover:underline"
                >
                  <Download className="mr-1" size={16} />
                  Download Image
                </a>
              </div>
            )}
          </motion.div>
          
          {/* Image Enhancement Section */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3, duration: 0.5 }}
            className="bg-gradient-to-br from-blue-50 to-teal-50 dark:from-blue-900/20 dark:to-teal-900/10 p-6 rounded-lg border border-blue-100 dark:border-blue-800/30"
          >
            <h2 className="text-xl font-semibold mb-4 flex items-center text-blue-700 dark:text-blue-400">
              <Zap className="mr-2" size={24} />
              Enhance Existing Image
            </h2>
            
            <div className="space-y-4">
              <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center">
                <input
                  type="file"
                  accept="image/*"
                  ref={fileInputRef}
                  onChange={handleImageUpload}
                  className="hidden"
                />
                <ImageIcon className="mx-auto mb-4 text-gray-400" size={48} />
                <p className="mb-2 text-gray-600 dark:text-gray-300">
                  {image ? image.name : 'Upload an image to enhance'}
                </p>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="bg-blue-100 dark:bg-blue-800/30 hover:bg-blue-200 dark:hover:bg-blue-700/30 text-blue-700 dark:text-blue-300 font-medium py-2 px-4 rounded-lg transition-colors duration-200"
                >
                  Choose Image
                </button>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Enhancement Instructions
                </label>
                <textarea
                  value={enhancePrompt}
                  onChange={(e) => setEnhancePrompt(e.target.value)}
                  placeholder="Describe how you want to enhance the image..."
                  className="w-full h-32 bg-white dark:bg-gray-700 text-gray-800 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg py-3 px-4 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              
              <button
                onClick={handleEnhanceImage}
                disabled={!image || !enhancePrompt || enhanceLoading}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center"
              >
                {enhanceLoading ? (
                  <>
                    <Loader className="animate-spin mr-2" size={20} />
                    Enhancing...
                  </>
                ) : (
                  <>
                    <Zap className="mr-2" size={20} />
                    Enhance Image
                  </>
                )}
              </button>
            </div>
            
            {enhancementResult && (
              <div className="mt-6">
                <h3 className="text-lg font-medium mb-2 text-blue-700 dark:text-blue-400">Enhancement Results</h3>
                <div className="bg-white dark:bg-gray-800 border border-blue-200 dark:border-blue-800/50 rounded-lg p-4">
                  <p className="text-gray-700 dark:text-gray-200 whitespace-pre-line">{enhancementResult}</p>
                </div>
              </div>
            )}
          </motion.div>
        </div>
        
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-6 border border-purple-100 dark:border-purple-800">
            <h3 className="text-lg font-semibold mb-3 text-purple-700 dark:text-purple-400">About OxImaGen</h3>
            <p className="text-gray-600 dark:text-gray-300">
              OxImaGen uses advanced AI models to generate and enhance images. Create original artwork, modify existing images, or transform concepts into visual representations.
            </p>
          </div>
          
          <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-6 border border-blue-100 dark:border-blue-800">
            <h3 className="text-lg font-semibold mb-3 text-blue-700 dark:text-blue-400">Tips for Better Results</h3>
            <p className="text-gray-600 dark:text-gray-300">
              For best results, provide detailed descriptions with specific styles, lighting, colors, and composition. The more specific your prompt, the better the AI can match your vision.
            </p>
          </div>
        </div>
      </motion.div>
    </Layout>
  )
}

export default OxImaGen


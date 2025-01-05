'use client'

import React from 'react'
import Layout from '../../../components/Layout'
import { motion } from 'framer-motion'
import { FileText, Search, Mic, Volume, File, Link2, FileMinus, Headphones } from 'lucide-react'

export default function OxRAGDocs() {
  return (
    <Layout>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="max-w-4xl mx-auto"
      >
        <h2 className="text-3xl font-semibold text-gray-800 dark:text-white mb-6">
          OxRAG Documentation <FileText className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
        </h2>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Overview <Search className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxRAG is your cybersecurity research companion powered by the Gemini API, designed to analyze various documents, extract key insights, create embeddings, and support advanced question-answering (Q&A). The tool integrates seamlessly with text-to-speech capabilities for enhanced interactivity.
          </p>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Frameworks & Technologies <File className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li><strong>Streamlit:</strong> Sleek and interactive interface for a seamless user experience.</li>
            <li><strong>FAISS:</strong> Efficient similarity search and clustering for dense vectors.</li>
            <li><strong>Pandas:</strong> Proficient data handling for files like CSV, Excel, and more.</li>
            <li><strong>PyPDF2:</strong> Extracts text from PDFs for easy processing.</li>
            <li><strong>BeautifulSoup:</strong> Scrapes web data with precision.</li>
            <li><strong>gTTS:</strong> Converts text to speech for voice output.</li>
            <li><strong>Google Generative AI (GenAI):</strong> Leverages the power of Gemini API for intelligent queries.</li>
            <li><strong>SpeechRecognition:</strong> Converts voice input for hands-free interaction.</li>
          </ul>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Architecture <Link2 className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            OxRAG's architecture consists of multiple layers designed to handle input, process it, generate embeddings, and provide insightful responses.
          </p>
          <ul className="list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li><strong>Input Handling:</strong> Users can upload files (PDF, CSV, Excel, JSON), paste article URLs, or provide text or voice input.</li>
            <li><strong>Text Extraction:</strong> Extracts text from various inputs, including documents and web pages.</li>
            <li><strong>Embedding Creation:</strong> Converts extracted text into embeddings stored in FAISS for fast similarity search.</li>
            <li><strong>Q&A System:</strong> Users can ask questions based on extracted text, with relevant context retrieved from the FAISS index and analyzed by the Gemini API.</li>
            <li><strong>Response Generation:</strong> Provides answers in text format or speech, depending on user preferences.</li>
          </ul>
        </section>

        <section className="mb-12">
        <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-6">
            How to Use <Mic className="inline-block ml-2 text-gray-600 dark:text-gray-400"/>
        </h3>
        <ol className="list-decimal list-inside text-gray-600 dark:text-gray-400 space-y-6 pl-6">
            <li className="space-y-2">
            <span className="font-semibold text-gray-800 dark:text-white">Access OxImaGen:</span>
            <p className="text-gray-600 dark:text-gray-400">Navigate to the OxImaGen section in your OxSuite application from the dashboard.</p>
            </li>
            <li className="space-y-2">
            <span className="font-semibold text-gray-800 dark:text-white">Upload an image:</span>
            <p className="text-gray-600 dark:text-gray-400">Use the upload feature to select an image for analysis, or proceed to generate a new image.</p>
            </li>
            <li className="space-y-2">
            <span className="font-semibold text-gray-800 dark:text-white">Generate an image:</span>
            <p className="text-gray-600 dark:text-gray-400">Click the "Generate" button to create a new image based on AI algorithms. You can customize parameters such as theme, style, and size.</p>
            </li>
            <li className="space-y-2">
            <span className="font-semibold text-gray-800 dark:text-white">Analyze the image:</span>
            <p className="text-gray-600 dark:text-gray-400">Once an image is uploaded or generated, OxImaGen will automatically analyze it for potential security threats.</p>
            </li>
            <li className="space-y-2">
            <span className="font-semibold text-gray-800 dark:text-white">Review results:</span>
            <p className="text-gray-600 dark:text-gray-400">Examine the analysis results, which may include detected vulnerabilities, potential risks, or areas of concern. You can also listen to the results via text-to-speech.</p>
            </li>
        </ol>
        </section>


        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Features <Volume className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li><strong>Text Extraction:</strong> Automatically extracts text from files or URLs for further analysis.</li>
            <li><strong>Embedding Storage:</strong> Stores text embeddings in FAISS for fast retrieval.</li>
            <li><strong>Q&A Functionality:</strong> Advanced question-answering capabilities based on the extracted text.</li>
            <li><strong>Text-to-Speech:</strong> Convert the generated responses into speech for a more interactive experience.</li>
            <li><strong>Voice Recognition:</strong> Hands-free interaction with voice commands.</li>
          </ul>
        </section>

        <section className="mb-8">
          <h3 className="text-2xl font-semibold text-gray-700 dark:text-gray-300 mb-4">
            Best Practices <Headphones className="inline-block ml-2 text-gray-600 dark:text-gray-400" />
          </h3>
          <ul className="list-disc list-inside text-gray-600 dark:text-gray-400 space-y-2">
            <li>Upload high-quality documents for optimal text extraction and embedding results.</li>
            <li>Regularly update the model with new data for more accurate and relevant responses.</li>
            <li>Utilize the Q&A feature to gain insights and answers directly from the analyzed content.</li>
            <li>Explore voice recognition for a hands-free, efficient research process.</li>
          </ul>
        </section>
      </motion.div>
    </Layout>
  )
}
